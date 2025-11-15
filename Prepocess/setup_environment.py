import os
import sys
import platform
import urllib.request
import subprocess
import tempfile

def check_os():
    """Kiểm tra hệ điều hành"""
    system = platform.system().lower()
    if system == "windows":
        return "windows"
    elif system == "linux":
        return "linux" 
    elif system == "darwin":
        return "macos"
    else:
        return "unknown"

def ensure_pip():
    """Đảm bảo pip đã được cài đặt"""
    print("Kiểm tra pip...")
    try:
        # Thử import pip
        import pip
        print("✓ Pip đã được cài đặt")
        return True
    except ImportError:
        print("✗ Pip chưa được cài đặt. Đang cài đặt pip...")
        return install_pip()

def install_pip():
    """Cài đặt pip nếu chưa có"""
    try:
        # Tải get-pip.py và chạy
        print("Đang tải get-pip.py...")
        url = "https://bootstrap.pypa.io/get-pip.py"
        temp_file = os.path.join(tempfile.gettempdir(), "get-pip.py")
        
        urllib.request.urlretrieve(url, temp_file)
        
        print("Đang cài đặt pip...")
        result = subprocess.run([sys.executable, temp_file], capture_output=True, text=True)
        
        if result.returncode == 0:
            print("✓ Đã cài đặt pip thành công")
            # Xóa file tạm
            try:
                os.remove(temp_file)
            except:
                pass
            return True
        else:
            print(f"✗ Lỗi khi cài đặt pip: {result.stderr}")
            return False
            
    except Exception as e:
        print(f"✗ Lỗi khi cài đặt pip: {e}")
        return False

def install_package(package):
    """Cài đặt package sử dụng pip"""
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", package])
        print(f"✓ Đã cài đặt: {package}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"✗ Lỗi khi cài đặt {package}: {e}")
        return False
    except Exception as e:
        print(f"✗ Lỗi không xác định với {package}: {e}")
        return False

def install_requirements():
    """Cài đặt tất cả các thư viện cần thiết"""
    
    # Danh sách các package cần cài đặt
    packages = [
        "pandas",
        "numpy", 
        "scikit-learn",
        "scipy",
        "requests",
        "packaging",
        "tree-sitter",
        "tree-sitter-javascript",
        "prettytable"
    ]
    
    print("=" * 60)
    print("BẮT ĐẦU CÀI ĐẶT THƯ VIỆN CẦN THIẾT")
    print("=" * 60)
    
    # Kiểm tra hệ điều hành
    os_type = check_os()
    print(f"Hệ điều hành: {os_type}")
    print(f"Python version: {sys.version}")
    print()
    
    # Đảm bảo pip đã được cài đặt
    if not ensure_pip():
        print("Không thể cài đặt pip. Vui lòng cài đặt thủ công.")
        return False
    
    # Cập nhật pip trước
    print("Đang cập nhật pip...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", "pip"])
        print("✓ Đã cập nhật pip")
    except:
        print("⚠ Không thể cập nhật pip, tiếp tục cài đặt bình thường...")
    
    # Cài đặt từng package
    success_count = 0
    failed_packages = []
    
    for package in packages:
        print(f"\nĐang cài đặt {package}...")
        if install_package(package):
            success_count += 1
        else:
            failed_packages.append(package)
    
    # Thông báo kết quả
    print("\n" + "=" * 60)
    print("KẾT QUẢ CÀI ĐẶT")
    print("=" * 60)
    print(f"Thành công: {success_count}/{len(packages)}")
    
    if failed_packages:
        print(f"Thất bại: {', '.join(failed_packages)}")
        print("\nĐể cài đặt thủ công, chạy lệnh:")
        for pkg in failed_packages:
            print(f"python -m pip install {pkg}")
        
        # Thử cài đặt lại các package bị lỗi với options đặc biệt
        print("\nThử cài đặt lại với pre-built wheels...")
        for pkg in failed_packages[:]:  # Copy list để tránh modify while iterating
            print(f"Thử cài đặt lại {pkg}...")
            try:
                # Thử với --prefer-binary để tránh compile
                subprocess.check_call([
                    sys.executable, "-m", "pip", "install", 
                    "--prefer-binary", pkg
                ])
                print(f"✓ Đã cài đặt thành công: {pkg}")
                success_count += 1
                failed_packages.remove(pkg)
            except:
                print(f"✗ Vẫn lỗi với: {pkg}")
    else:
        print("✓ Tất cả thư viện đã được cài đặt thành công!")
    
    return len(failed_packages) == 0

def verify_installation():
    """Xác minh tất cả các thư viện có thể import được"""
    print("\n" + "=" * 60)
    print("XÁC MINH IMPORT THƯ VIỆN")
    print("=" * 60)
    
    libraries = [
        ("os", "os"),
        ("json", "json"), 
        ("math", "math"),
        ("hashlib", "hashlib"),
        ("csv", "csv"),
        ("re", "re"),
        ("pathlib", "Path"),
        ("collections", "Counter"),
        ("datetime", "datetime"),
        ("packaging.version", "Version, InvalidVersion"),
        ("tree_sitter", "Language, Parser"),
        ("tree_sitter_javascript", "tsjs"),
        ("time", "time"),
        ("requests", "requests"),
        ("subprocess", "subprocess"),
        ("tarfile", "tarfile"),
        ("shutil", "shutil"),
        ("platform", "platform"),
        ("sys", "sys"),
        ("zipfile", "zipfile"),
        ("random", "random"),
        ("pandas", "pd"),
        ("numpy", "np"),
        ("sklearn.model_selection", "StratifiedKFold"),
        ("sklearn.preprocessing", "StandardScaler"),
        ("prettytable", "PrettyTable")
    ]
    
    all_success = True
    
    for lib, imports in libraries:
        try:
            if lib == "tree_sitter_javascript":
                import tree_sitter_javascript as tsjs
            elif lib == "sklearn.model_selection":
                from sklearn.model_selection import StratifiedKFold
            elif lib == "sklearn.preprocessing":
                from sklearn.preprocessing import StandardScaler
            elif "." in lib:
                # Cho các import từ module con
                module_name, attr_name = lib.split(".", 1)
                module = __import__(module_name, fromlist=[attr_name])
            else:
                module = __import__(lib)
            
            print(f"✓ {lib}: OK")
        except ImportError as e:
            print(f"✗ {lib}: LỖI - {e}")
            all_success = False
        except Exception as e:
            print(f"⚠ {lib}: CẢNH BÁO - {e}")
    
    return all_success

def manual_installation_guide():
    """Hướng dẫn cài đặt thủ công nếu tự động thất bại"""
    print("\n" + "=" * 60)
    print("HƯỚNG DẪN CÀI ĐẶT THỦ CÔNG")
    print("=" * 60)
    print("1. Mở Command Prompt với quyền Administrator")
    print("2. Chạy các lệnh sau:")
    print("   python -m ensurepip --upgrade")
    print("   python -m pip install --upgrade pip")
    print("3. Sau đó chạy từng lệnh:")
    print("   python -m pip install pandas numpy scikit-learn scipy")
    print("   python -m pip install requests packaging prettytable")
    print("   python -m pip install tree-sitter tree-sitter-javascript")
    print("\nNếu vẫn lỗi, thử:")
    print("   python -m pip install --prefer-binary pandas numpy scikit-learn")

if __name__ == "__main__":
    # Cài đặt các thư viện
    success = install_requirements()
    
    # Xác minh cài đặt
    if success:
        verify_success = verify_installation()
        if verify_success:
            print("\nTẤT CẢ THƯ VIỆN ĐÃ SẴN SÀNG!")
            print("Bạn có thể chạy các script của mình bình thường.")
        else:
            print("\n⚠ MỘT SỐ THƯ VIỆN CÓ VẤN ĐỀ!")
            manual_installation_guide()
    else:
        print("\nCÀI ĐẶT TỰ ĐỘNG THẤT BẠI!")
        manual_installation_guide()
    
    print("\nNhấn Enter để thoát...")
    input()
