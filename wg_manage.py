import ipaddress
import subprocess
from json import dump, load


class Var:
    # 网卡选择菜单
    choose_ifname: dict[int, str] = {}
    # 网卡数据
    vpn_data: dict[str, dict] = {}

    now_ifname = ""  # WG网卡名称
    prikey = ""  # 服务器私钥
    pubkey = ""  # 服务器公钥
    endpoint = ""  # VPN服务器地址
    listen_port = ""  # 监听端口
    allowips = ""  # 路由
    network = ipaddress.ip_network("1.1.1.1/32")  # VPN网段
    gateway = ""  # 网关
    available_ips: list[str] = []  # 可分配IP


var = Var()


def write_file(file_path: str, file_text: str):
    with open(file_path, "w", encoding="utf-8") as w:
        w.write(file_text)


def exec_shell(command: str, input: str | None = None) -> str:
    result = subprocess.run(
        command, input=input, capture_output=True, text=True, shell=True
    )
    return result.stderr.strip() if result.returncode else result.stdout.strip()


def read_data():
    try:
        with open("vpn_data.json", "r", encoding="utf-8") as r:
            var.vpn_data = load(r)
    except FileNotFoundError:
        print("未发现vpn_data.json")


def save_data():
    with open("vpn_data.json", "w", encoding="utf-8") as w:
        dump(var.vpn_data, w, indent=4, ensure_ascii=False)


def general_server():
    ifname = input("请输入网卡名：")
    endpoint = input("请输入服务器地址，格式host:port：")
    network = input("请输入网段，格式1.1.1.0/24：")
    allowips = input("请输入路由，格式1.1.1.0/24，多个用英文逗号分割：")
    print(
        f"请确认网卡信息\n名称：{ifname}\n服务器地址：{endpoint}\n网段：{network}\n路由：{allowips}"
    )

    confirm = input("没问题输入y/Y：")
    if confirm.lower() != "y":
        print("操作取消")
        return

    prikey = exec_shell("wg genkey")  # 生成私钥
    pubkey = exec_shell("wg pubkey", input=prikey)  # 生成公钥

    listen_port = endpoint.split(":")[-1]
    # 获取广播地址的前一个地址作为网关地址
    gateway = str(ipaddress.ip_network(network).broadcast_address - 1)
    netmask = network.split("/")[-1]

    conf_text = f"""[Interface]
ListenPort = {listen_port}
Address = {gateway}/{netmask}
PrivateKey = {prikey}"""

    write_file(f"/etc/wireguard/{ifname}.conf", conf_text)
    print(f"网卡信息已写入文件 /etc/wireguard/{ifname}.conf")

    confirm = input("启动网卡输入y/Y：")
    if confirm.lower() == "y":
        print(exec_shell(f"wg-quick up {ifname}"))
        print("启动网卡执行完毕")

    new_if_data = {
        ifname: {
            "server": {
                "prikey": prikey,
                "pubkey": pubkey,
                "endpoint": endpoint,
                "network": network,
                "allowips": allowips,
            },
            "client": {},
        }
    }
    var.vpn_data.update(new_if_data)
    save_data()


def read_if(ifname: str):
    server_data: dict[str, str] = var.vpn_data[ifname]["server"]

    var.now_ifname = ifname
    var.prikey = server_data["prikey"]
    var.pubkey = server_data["pubkey"]
    var.endpoint = server_data["endpoint"]
    var.listen_port = var.endpoint.split(":")[-1]
    var.allowips = server_data["allowips"]
    var.network = ipaddress.ip_network(server_data["network"])
    # 获取广播地址的前一个地址作为网关地址
    var.gateway = str(var.network.broadcast_address - 1)

    # 获取可分配IP
    for ip in var.network.hosts():
        str_ip = str(ip)
        if str_ip in var.vpn_data[ifname]["client"].keys() or str_ip == var.gateway:
            continue

        var.available_ips.append(str_ip)

    if not var.available_ips:
        print(f"网卡 {ifname} 的IP池已耗尽")


def insert_client(ifname: str, clients: dict[str, dict[str, str]]):
    insert_peer_list: list[str] = []
    for ip, info in clients.items():
        insert_peer_list.append(
            f"wg set {ifname} peer {info['pubkey']} allowed-ips {ip}/32;"
        )
    if insert_peer_list:
        # 每10一组执行，插入wg peer
        list_len = len(insert_peer_list)
        for i in range(0, list_len, 10):
            batch = insert_peer_list[i : i + 10]
            insert_peer_cmd = ""
            for cmd in batch:
                insert_peer_cmd += cmd
            exec_shell(insert_peer_cmd)

    print(f"载入客户端信息{list_len}个")


def general_client(user: str):
    ip = var.available_ips.pop(0)
    prikey = exec_shell("wg genkey")  # 生成私钥
    pubkey = exec_shell("wg pubkey", input=prikey)  # 生成公钥
    netmask = str(var.network).split("/")[-1]
    # 生成配置文件
    tunnel_text = f"""[Interface]
PrivateKey = {prikey}
Address = {ip}/{netmask}

[Peer]
PublicKey = {var.pubkey}
Endpoint = {var.endpoint}
AllowedIPs = {var.allowips}
PersistentKeepalive = 30"""
    # 把新配置写入wg
    exec_shell(f"wg set {var.now_ifname} peer {pubkey} allowed-ips {ip}/32")
    # 生成conf
    write_file(f"{ip}.conf", tunnel_text)
    print(f"已输出{user}的客户端配置 {ip}.conf")

    # 持久化数据
    new_user_data = {
        ip: {
            "user": user,
            "prikey": prikey,
            "pubkey": pubkey,
        }
    }
    var.vpn_data[var.now_ifname]["client"].update(new_user_data)
    var.vpn_data[var.now_ifname]["client"] = dict(
        sorted(
            var.vpn_data[var.now_ifname]["client"].items(),
            key=lambda item: ipaddress.ip_address(item[0]),
        )
    )
    save_data()


def remove_client(ip: str):
    info = var.vpn_data[var.now_ifname]["client"][ip]
    user = info["user"]
    pubkey = info["pubkey"]

    print(f"请确认移除的客户端信息\n用户：{user}  IP：{ip}")

    confirm = input("确定移除吗 y/Y：")
    if confirm.lower() != "y":
        print("操作取消")
        return

    exec_shell(f"wg set {var.now_ifname} peer {pubkey} remove")

    var.vpn_data[var.now_ifname]["client"].pop(ip)

    print(f"已移除 {user} 的客户端配置")

    save_data()


def general_conf(ip: str):
    info = var.vpn_data[var.now_ifname]["client"][ip]
    user = info["user"]
    prikey = info["prikey"]
    netmask = str(var.network).split("/")[-1]
    # 生成配置文件
    tunnel_text = f"""[Interface]
PrivateKey = {prikey}
Address = {ip}/{netmask}

[Peer]
PublicKey = {var.pubkey}
Endpoint = {var.endpoint}
AllowedIPs = {var.allowips}
PersistentKeepalive = 30"""
    # 生成conf
    write_file(f"{ip}.conf", tunnel_text)
    print(f"已输出{user}的客户端配置 {ip}.conf")


#  保存iptables
# exec_shell("iptables-save > /home/iptables/rules.v4")


def if_operation(ifname: str):
    read_if(ifname)

    while True:
        print(
            f"""
###  网卡 {ifname} 菜单  ###
# 地址: {var.endpoint}
# 网段: {var.network}
# 路由: {var.allowips}
# 客户端数: {len(var.vpn_data[ifname]['client'])}
0 - 返回主菜单
1 - 启动网卡
2 - 关闭网卡
3 - 列出客户端
4 - 添加客户端
5 - 删除客户端
6 - 重新输出conf
9 - 重启网卡"""
        )

        choice = int(input("请输入代码："))

        if choice == 0:
            print("返回主菜单")
            break

        elif choice == 1:
            print(f"将启动网卡 {ifname}")
            exec_shell(f"wg-quick up {ifname}")
            if var.vpn_data[ifname]["client"]:
                insert_client(ifname, var.vpn_data[ifname]["client"])

        elif choice == 2:
            print(f"将关闭网卡 {ifname}")
            exec_shell(f"wg-quick down {ifname}")

        elif choice == 3:
            if var.vpn_data[ifname]["client"]:
                print(f"客户端信息如下")
                for ip, info in var.vpn_data[ifname]["client"].items():
                    print(f"{ip} - {info['user']}")
            else:
                print("没有客户端")

        elif choice == 4:
            add_user = input("请输入要添加的用户名：")
            general_client(add_user)

        elif choice == 5:
            del_ip = input("请输入要删除的客户端IP：")
            if del_ip in var.vpn_data[ifname]["client"]:
                remove_client(del_ip)
            else:
                print(f"{del_ip}不存在")

        elif choice == 6:
            conf_ip = input("请输入要输出的客户端IP：")
            if conf_ip in var.vpn_data[ifname]["client"]:
                general_conf(conf_ip)
            else:
                print(f"{conf_ip}不存在")

        elif choice == 9:
            print(f"将重启网卡 {ifname}")
            exec_shell(f"wg-quick down {ifname}")
            exec_shell(f"wg-quick up {ifname}")
            if var.vpn_data[ifname]["client"]:
                insert_client(ifname, var.vpn_data[ifname]["client"])

        else:
            print(f"未知代码{choice}，请重新选择")

        input("<< 按回车继续 >>")


def main():
    read_data()

    while True:
        print("\n###  主菜单  ###\n0 - 新建WG网卡")
        for index, ifname in enumerate(var.vpn_data, 1):
            var.choose_ifname[index] = ifname
            print(f"{index} - {ifname}")

        choice = input("请输入代码：")

        if int(choice) == 0:
            print("开始新建WG网卡流程")
            general_server()

        elif int(choice) in var.choose_ifname:
            choose_ifname = var.choose_ifname[int(choice)]
            print(f"选择网卡 {choose_ifname}")
            if_operation(choose_ifname)

        else:
            print(f"未知代码{choice}，请重新选择")

        input("<< 按回车继续 >>")


try:
    main()
except KeyboardInterrupt:
    pass
