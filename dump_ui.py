import xml.etree.ElementTree as ET, subprocess

xml_data = subprocess.check_output(['adb', '-s', '192.168.0.3:34303', 'shell', 'cat', '/sdcard/ui_chrome.xml']).decode('utf-8', errors='ignore')
root = ET.fromstring(xml_data)
for node in root.iter('node'):
    text = node.attrib.get('text', '')
    desc = node.attrib.get('content-desc', '')
    res_id = node.attrib.get('resource-id', '')
    if text or desc:
        print(f'{res_id} -> text="{text}" desc="{desc}"')
