# ----------------------------
# 导入必要模块
# ----------------------------
import sys
from securecrt_password_extractor import main as extract_main


def main():
    try:
        # 直接调用提取程序主函数，不传递任何参数
        extract_main()
        # 执行完成后暂停，避免窗口自动关闭
        input("\n密码提取完成，按Enter键退出...")
    except Exception as e:
        print(f"操作失败: {str(e)}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
