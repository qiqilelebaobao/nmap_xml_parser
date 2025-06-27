import pandas as pd
import xml.etree.ElementTree as ET
import os
from typing import List, Dict, Any
import json
from datetime import datetime


def parse_ssl_vulnerabilities(xml_path: str) -> List[Dict[str, str]]:
    """
    解析XML文件中的SSL漏洞信息
    :param xml_path: XML文件路径
    :return: 包含主机信息和漏洞协议的列表
    """

    if not os.path.isfile(xml_path):
        print(f"警告：文件 {xml_path} 不存在，跳过解析")
        return []

    try:
        tree = ET.parse(xml_path)  # 添加异常处理，防止解析无效XML文件导致程序崩溃
    except ET.ParseError as e:
        print(f"警告：文件 {xml_path} 格式错误，无法解析 - {str(e)}")
        return []

    root = tree.getroot()
    hosts = []

    for host in root.findall('host'):
        hostname_element = host.find('hostnames/hostname')
        address_element = host.find('address')

        if hostname_element is None or address_element is None:
            continue

        hostname = hostname_element.get('name')
        ip_addr = address_element.get('addr')

        if hostname is None or ip_addr is None:
            continue

        # for port in host.find('ports').findall('port'):
        # for port in host.findall('.//port'):
        for port in host.iter('port'):
            script = port.find('script')
            if script is None:
                continue

            output = script.get('output', '')

            protocols = []
            for proto in ['TLSv1.0', 'TLSv1.1']:
                if proto in output:
                    protocols.append(proto)

            if protocols:
                hosts.append({
                    'host': hostname,
                    'ip_addr': ip_addr,
                    'port': port.get('portid', 'unknown'),
                    'protocols': ' & '.join(protocols)
                }
                )

    return hosts


def print_hosts(hosts) -> None:
    """
    以表格格式打印主机信息
    :param hosts: 包含主机信息的列表
    """
    if not hosts:
        print("没有发现支持旧协议的主机")
        return

    print(f"\n{'ID':<6}{'Host':<36}{'IP':<20}{'Port':<8}{'Vulnerable Protocols'}")
    line_len = 6 + 36 + 20 + 8 + \
        max(len('Vulnerable Protocols'), len('TLSv1.0 & TLSv1.1'))

    print("-" * line_len)
    for i, item in enumerate(hosts, 1):
        hostname_display = (
            item['host'][:34] + '..') if len(item['host']) > 34 else item['host']  # 修改：使用更清晰的变量名
        print(
            f"{i:<6}{hostname_display:<36}{item['ip_addr']:<20}{item['port']:<8}{item['protocols']}")
    print("-" * line_len)


def parse_multiple_files(file_paths: List[str]) -> List[Dict[str, str]]:
    """
    解析多个XML文件
    :param file_paths: XML文件路径列表
    :return: 合并后的主机信息列表
    """
    all_hosts = []
    for file_path in file_paths:
        print(f"正在解析 {file_path}...")
        hosts = parse_ssl_vulnerabilities(file_path)
        all_hosts.extend(hosts)
    return all_hosts


def export_to_csv(hosts: List[Dict[str, Any]], output_path: str) -> str:
    """
    将结果导出为CSV文件
    :param hosts: 主机信息列表
    :param output_path: 输出文件路径
    """
    if not hosts:
        print("没有数据可导出")
        return ''

    with open(output_path, 'w') as f:
        headers = ["ID", "Host", "IP", "Port", "Vulnerable Protocols"]
        f.write(','.join(headers) + '\n')

        for i, item in enumerate(hosts, 1):
            row = [str(i), item['host'], item['ip_addr'],
                   item['port'], item['protocols']]
            f.write(','.join(row) + '\n')

    print(f"数据已导出到 {output_path}")

    return output_path


def export_to_json(hosts: List[Dict[str, Any]], output_path: str) -> None:
    """
    将结果导出为JSON文件
    :param hosts: 主机信息列表
    :param output_path: 输出文件路径
    """
    if not hosts:
        print("没有数据可导出")
        return

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(hosts, f, indent=2, ensure_ascii=False)

    print(f"数据已导出到 {output_path}")


def get_export_filename(base_name: str, ext: str) -> str:
    """
    根据基础文件名和扩展名生成导出文件名
    :param base_name: 基础文件名
    :param ext: 文件扩展名
    :return: 完整的导出文件路径
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{os.path.splitext(base_name)[0]}_{timestamp}.{ext}"


def get_xml_domain(xml_path: str, output_file: str = 'test_domain.txt') -> None:
    """
    从 XML 文件中提取域名信息并保存到指定文件。
    :param xml_path: XML 文件路径
    :param output_file: 输出文件路径，默认为 'test_domain.txt'
    """
    if not os.path.isfile(xml_path):
        print(f"警告：文件 {xml_path} 不存在，跳过解析")

    try:
        tree = ET.parse(xml_path)  # 添加异常处理，防止解析无效XML文件导致程序崩溃
    except ET.ParseError:
        print(f"警告：文件 {xml_path} 格式错误，无法解析")
        return

    root = tree.getroot()

    # 提取硬编码的 XML 路径以提高可维护性
    HOSTNAMES_PATH = 'hostnames/hostname'
    NAME_ATTR = 'name'

    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            for host in root.findall('host'):
                hostname = host.find(HOSTNAMES_PATH).get(  # type: ignore
                    NAME_ATTR)  # type: ignore
                print(hostname, file=f)
    except IOError as e:
        print(f"警告：无法写入文件 {output_file} - {str(e)}")


def csv_to_excel(base_name: str, csv_encoding: str = 'utf-8') -> None:
    """
    将 CSV 文件转换为 Excel 文件
    :param base_name: 基础文件名
    :param csv_encoding: CSV 文件的编码格式，默认为 'utf-8'
    """
    csv_file = f'{os.path.splitext(base_name)[0]}.csv'
    excel_file = f'{os.path.splitext(base_name)[0]}.xlsx'

    try:
        # 读取 CSV 文件
        df = pd.read_csv(csv_file, encoding=csv_encoding)

        # 写入 Excel 文件
        df.to_excel(excel_file, index=False, engine='openpyxl')

        print(f"CSV 文件已成功转换为 Excel 文件：{excel_file}")

    except FileNotFoundError:
        print(f"警告：文件 {csv_file} 不存在，跳过转换")
    except Exception as e:
        print(f"警告：转换文件时出错 - {str(e)}")


if __name__ == '__main__':

    xml_files = ['ssl_0625.xml']

    hosts = parse_multiple_files(xml_files)
    # print_hosts(hosts)

    base_name = xml_files[0]

    csv_name = export_to_csv(hosts, get_export_filename(base_name, 'csv'))
    # export_to_json(hosts, get_export_filename(base_name, 'json'))
    if csv_name:
        csv_to_excel(csv_name)

    # get_xml_domain(xml_files[0])
