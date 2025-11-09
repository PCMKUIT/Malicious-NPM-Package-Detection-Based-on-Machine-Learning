import os
import time
import json
import requests
import subprocess
import tarfile
from datetime import datetime, timedelta
from pathlib import Path
import shutil
import platform
import sys

# Lấy thư mục hiện tại và tạo thư mục BenignDataset
CURRENT_DIR = Path(__file__).parent
OUTPUT_ROOT = CURRENT_DIR / "BenignDataset"
SLEEP_INTERVAL = 3600
MAX_PACKAGES_TOTAL = 5000  # MỤC TIÊU: 5000 packages thành công
MAX_PACKAGES_PER_QUERY = 1000
VERSIONS_PER_PACKAGE = 5
PACKAGES_PER_PAGE = 250

# =============================================================================
# FEATURE CRITERIA CONFIGURATION - Based on Research Papers
# =============================================================================

class PackageCriteria:
    """Tiêu chí lọc packages dựa trên nghiên cứu học máy cho NPM malware detection"""
    
    # 1. SIZE CRITERIA - Loại bỏ packages không phù hợp về kích thước
    SIZE = {
        'MIN_SIZE_KB': 1,           # 1KB - Loại bỏ package quá nhỏ (empty/test packages)
        'MAX_SIZE_MB': 50,          # 50MB - Loại bỏ package quá lớn (thường chứa binary)
        'REASON': 'Theo nghiên cứu của Liu et al. (2021), malicious packages thường có kích thước từ 1KB-10MB'
    }
    
    # 2. CONTENT CRITERIA - Đảm bảo package có cấu trúc hợp lệ
    CONTENT = {
        'MIN_FILES': 2,             # Ít nhất 2 files (package.json + ít nhất 1 file code)
        'REQUIRED_FILES': ['package.json'],  # Phải có package.json
        'EXCLUDE_EXTENSIONS': ['.exe', '.dll', '.bin', '.so', '.dylib'],  # Loại binary files
        'REASON': 'Zhou et al. (2022) chỉ ra packages hợp lệ cần có cấu trúc NPM chuẩn'
    }
    
    # 3. METADATA CRITERIA - Kiểm tra thông tin mô tả package
    METADATA = {
        'VALID_JSON': True,         # package.json phải parse được
        'HAS_MAIN_OR_INDEX': True,  # Có main field hoặc index.js
        'VALID_VERSION': True,      # Version phải theo semantic versioning
        'REASON': 'Ohm et al. (2020) xác định metadata integrity quan trọng cho classification'
    }
    

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'

def get_npm_token():
    """Lấy npm token từ environment variable hoặc CLI argument"""
    # Ưu tiên từ environment variable
    token = os.environ.get('NPM_TOKEN')
    
    # Nếu không có, thử từ CLI arguments
    if not token and len(sys.argv) > 1:
        token = sys.argv[1]
    
    return token

def find_npm_path():
    """Tìm đường dẫn npm trên mọi nền tảng"""
    system = platform.system()
    
    # Danh sách đường dẫn cho từng OS
    possible_paths = []
    
    if system == "Windows":
        possible_paths = [
            r"C:\Program Files\nodejs\npm.cmd",
            r"C:\Program Files\nodejs\npm",
            os.path.join(os.environ.get('APPDATA', ''), "npm", "npm.cmd"),
            shutil.which("npm"),
            "npm"
        ]
    else:  # Linux và macOS
        possible_paths = [
            "/usr/local/bin/npm",
            "/usr/bin/npm",
            "/opt/homebrew/bin/npm",  # macOS with Homebrew
            os.path.join(os.path.expanduser("~"), ".nvm", "versions", "node", "*", "bin", "npm"),
            shutil.which("npm"),
            "npm"
        ]
    
    for path in possible_paths:
        if path and (shutil.which(path) or os.path.isfile(path)):
            return path
        
        # Xử lý glob pattern cho nvm
        if "*" in path:
            import glob
            matches = glob.glob(path)
            if matches:
                return matches[0]
    
    # Fallback: tìm qua node path
    node_path = shutil.which("node")
    if node_path:
        if system == "Windows":
            npm_path = os.path.join(os.path.dirname(node_path), "npm.cmd")
        else:
            npm_path = os.path.join(os.path.dirname(node_path), "npm")
        
        if os.path.isfile(npm_path):
            return npm_path
    
    raise FileNotFoundError("Cannot find npm. Please install Node.js from https://nodejs.org/")

def count_total_successful_packages():
    """Đếm tổng số packages thành công trong TOÀN BỘ BenignDataset"""
    if not OUTPUT_ROOT.exists():
        return 0
    
    total_success = 0
    # Đếm từ TẤT CẢ log files
    for log_file in OUTPUT_ROOT.glob("*.log"):
        try:
            with open(log_file, 'r', encoding='utf-8') as f:
                for line in f:
                    if 'SUCCESS:' in line and 'Meets criteria' in line:
                        total_success += 1
        except Exception:
            continue
    return total_success

def meets_package_criteria(package_path):
    """
    Kiểm tra package có đạt tiêu chí nghiên cứu không
    Trả về (bool, reason)
    """
    try:
        # 1. Kiểm tra kích thước
        total_size = calculate_package_size(package_path)
        if total_size < PackageCriteria.SIZE['MIN_SIZE_KB'] * 1024:
            return False, f"Package too small: {total_size/1024:.1f}KB < {PackageCriteria.SIZE['MIN_SIZE_KB']}KB"
        
        if total_size > PackageCriteria.SIZE['MAX_SIZE_MB'] * 1024 * 1024:
            return False, f"Package too large: {total_size/(1024*1024):.1f}MB > {PackageCriteria.SIZE['MAX_SIZE_MB']}MB"
        
        # 2. Kiểm tra nội dung
        files = list_all_files(package_path)
        if len(files) < PackageCriteria.CONTENT['MIN_FILES']:
            return False, f"Not enough files: {len(files)} < {PackageCriteria.CONTENT['MIN_FILES']}"
        
        # Kiểm tra required files
        for req_file in PackageCriteria.CONTENT['REQUIRED_FILES']:
            if not any(req_file in file for file in files):
                return False, f"Missing required file: {req_file}"
        
        # Kiểm tra binary files
        for file in files:
            if any(file.endswith(ext) for ext in PackageCriteria.CONTENT['EXCLUDE_EXTENSIONS']):
                return False, f"Contains binary file: {file}"
        
        # 3. Kiểm tra metadata
        package_json_path = find_package_json(package_path)
        if package_json_path:
            try:
                with open(package_json_path, 'r', encoding='utf-8') as f:
                    package_data = json.load(f)
                
                # Kiểm tra version format
                if PackageCriteria.METADATA['VALID_VERSION']:
                    version = package_data.get('version', '')
                    if not is_valid_semver(version):
                        return False, f"Invalid version format: {version}"
                
                # Kiểm tra main entry point
                if PackageCriteria.METADATA['HAS_MAIN_OR_INDEX']:
                    main_file = package_data.get('main', 'index.js')
                    if not any(main_file in file for file in files) and not any('index.js' in file for file in files):
                        return False, "Missing main entry point (main field or index.js)"
                        
            except json.JSONDecodeError:
                return False, "Invalid package.json format"
        
        return True, "Meets all research criteria"
        
    except Exception as e:
        return False, f"Error checking criteria: {str(e)}"

def calculate_package_size(package_path):
    """Tính tổng kích thước package"""
    total_size = 0
    for file_path in package_path.rglob('*'):
        if file_path.is_file():
            total_size += file_path.stat().st_size
    return total_size

def list_all_files(package_path):
    """Liệt kê tất cả files trong package"""
    files = []
    for file_path in package_path.rglob('*'):
        if file_path.is_file():
            files.append(str(file_path.relative_to(package_path)))
    return files

def find_package_json(package_path):
    """Tìm file package.json"""
    package_json_path = package_path / 'package.json'
    if package_json_path.exists():
        return package_json_path
    return None

def is_valid_semver(version):
    """Kiểm tra version có theo semantic versioning không"""
    import re
    semver_pattern = r'^\d+\.\d+\.\d+(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$'
    return bool(re.match(semver_pattern, version)) if version else False

def get_popular_packages(max_packages, days_back=30):
    """Lấy các package phổ biến trong khoảng thời gian nhất định"""
    all_packages = []
    from_index = 0
    
    # Lấy token từ external source
    npm_token = get_npm_token()
    
    headers = {
        "Content-Type": "application/json"
    }
    
    # Chỉ thêm Authorization header nếu có token
    if npm_token:
        headers["Authorization"] = f"Bearer {npm_token}"
        print(f"  Using npm token for API requests")
    else:
        print(f"  {Colors.YELLOW}No npm token provided - using public API access (rate limits may apply){Colors.RESET}")
    
    # Thử nhiều ngày để đủ số lượng package
    for days_ago in range(days_back + 1):
        if len(all_packages) >= max_packages * 2:
            break
            
        search_date = (datetime.now() - timedelta(days=days_ago)).strftime("%Y-%m-%d")
        print(f"  Searching packages from {search_date}...")
        
        current_from_index = 0
        while len(all_packages) < max_packages * 2:
            # Tìm package phổ biến với sắp xếp theo quality
            api_url = f"https://registry.npmjs.org/-/v1/search?text=created:{search_date}&size={PACKAGES_PER_PAGE}&from={current_from_index}&popularity=1.0"
            
            try:
                response = requests.get(api_url, headers=headers, timeout=30)
                
                # XỬ LÝ RATE LIMIT - THÊM RETRY
                if response.status_code == 429:
                    print(f"    {Colors.YELLOW}Rate limit hit, waiting 5 seconds...{Colors.RESET}")
                    time.sleep(5)  # Chờ 5 giây
                    continue  # Thử lại request này, không chuyển ngày!
                    
                if response.status_code != 200:
                    print(f"    API returned status {response.status_code}")
                    break  # Chỉ break với lỗi khác 429
                    
                data = response.json()
                packages = data.get('objects', [])
                
                if not packages:
                    break
                
                # Lọc các package có score cao (phổ biến)
                high_score_packages = [
                    pkg for pkg in packages 
                    if pkg.get('score', {}).get('final', 0) > 0.5
                ]
                
                all_packages.extend(high_score_packages)
                current_from_index += len(packages)
                
                print(f"    Found {len(high_score_packages)} popular packages from {search_date} (total: {len(all_packages)})")
                
                if len(packages) < PACKAGES_PER_PAGE:
                    break
                    
                # Thêm delay nhẹ để tránh quá tải
                time.sleep(0.3)
                
            except Exception as e:
                print(f"    API error for {search_date}: {e}")
                break
    
    return all_packages[:max_packages * 2]

def get_package_versions(package_name, max_versions=5):
    """Lấy các version mới nhất của một package"""
    # Lấy token từ external source
    npm_token = get_npm_token()
    
    headers = {
        "Content-Type": "application/json"
    }
    
    # Chỉ thêm Authorization header nếu có token
    if npm_token:
        headers["Authorization"] = f"Bearer {npm_token}"
    
    try:
        # Lấy thông tin chi tiết package
        api_url = f"https://registry.npmjs.org/{package_name}"
        response = requests.get(api_url, headers=headers, timeout=30)
        
        if response.status_code != 200:
            return []
            
        data = response.json()
        versions = data.get('versions', {})
        
        # Sắp xếp version theo thời gian (mới nhất trước)
        sorted_versions = []
        for version_name, version_info in versions.items():
            # Ưu tiên version stable (không phải beta, alpha, rc)
            if any(keyword in version_name.lower() for keyword in ['beta', 'alpha', 'rc', 'next', 'unstable']):
                continue
                
            sorted_versions.append((version_name, version_info))
        
        # Sắp xếp theo version number (semantic versioning)
        def version_key(ver):
            version_str = ver[0]
            try:
                # Chuyển version string thành tuple số để so sánh
                parts = version_str.split('.')
                major = int(parts[0]) if parts[0].isdigit() else 0
                minor = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
                patch = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 0
                return (major, minor, patch)
            except:
                return (0, 0, 0)
        
        sorted_versions.sort(key=version_key, reverse=True)
        
        # Lấy max_versions version mới nhất
        selected_versions = []
        for version_name, version_info in sorted_versions[:max_versions]:
            selected_versions.append({
                'name': package_name,
                'version': version_name,
                'package_info': version_info
            })
        
        return selected_versions
        
    except Exception as e:
        print(f"    Error getting versions for {package_name}: {e}")
        return []

def write_to_log(daily_log_file, status, pkg_version_string, error_msg=None):
    """Ghi log với định dạng thống nhất"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if error_msg:
        log_entry = f"{timestamp} {status}: {pkg_version_string} - {error_msg}\n"
    else:
        log_entry = f"{timestamp} {status}: {pkg_version_string}\n"
    
    with open(daily_log_file, 'a', encoding='utf-8') as f:
        f.write(log_entry)

def create_summary_report(daily_log_file, summary_file, successful_downloads, filtered_packages, failed_downloads):
    """Tạo file summary report với thống kê chi tiết"""
    try:
        total_processed = successful_downloads + filtered_packages + failed_downloads
        
        with open(summary_file, 'w', encoding='utf-8') as f:
            f.write("=" * 60 + "\n")
            f.write(f"        BENIGN NPM PACKAGE COLLECTION SUMMARY REPORT\n")
            f.write("=" * 60 + "\n")
            f.write(f" Report Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f" Log File: {daily_log_file.name}\n")
            f.write("-" * 60 + "\n")
            f.write(" PACKAGE PROCESSING STATISTICS:\n")
            f.write(f" Successful: {successful_downloads:4d} packages ({successful_downloads/max(1,total_processed)*100:5.1f}%)\n")
            f.write(f" Filtered:   {filtered_packages:4d} packages ({filtered_packages/max(1,total_processed)*100:5.1f}%)\n")
            f.write(f" Failed:     {failed_downloads:4d} packages ({failed_downloads/max(1,total_processed)*100:5.1f}%)\n")
            f.write(f" Total:      {total_processed:4d} packages (100.0%)\n")
            f.write("-" * 60 + "\n")
            f.write(" RESEARCH CRITERIA APPLIED:\n")
            f.write(f" • Size: {PackageCriteria.SIZE['MIN_SIZE_KB']}KB - {PackageCriteria.SIZE['MAX_SIZE_MB']}MB\n")
            f.write(f" • Content: Min {PackageCriteria.CONTENT['MIN_FILES']} files, Required: {PackageCriteria.CONTENT['REQUIRED_FILES']}\n")
            f.write(f" • Metadata: Valid JSON, Main/Index.js, Semantic Versioning\n")
            f.write("-" * 60 + "\n")
            f.write(" PERFORMANCE METRICS:\n")
            f.write(f" Success Rate: {successful_downloads/max(1,total_processed)*100:5.1f}%\n")
            f.write(f" Filter Rate:  {filtered_packages/max(1,total_processed)*100:5.1f}%\n")
            f.write(f" Failure Rate: {failed_downloads/max(1,total_processed)*100:5.1f}%\n")
            f.write("=" * 60 + "\n")
        
        print(f"  Summary report created: {summary_file}")
        return True
    except Exception as e:
        print(f"  {Colors.RED}Failed to create summary report: {e}{Colors.RESET}")
        return False

def setup_npm_token():
    """Cấu hình npm token cho authentication"""
    try:
        npm_token = get_npm_token()
        if not npm_token:
            print(f"  {Colors.YELLOW}No npm token provided - skipping token configuration{Colors.RESET}")
            return False
            
        # Set npm token trong current process
        npm_path = find_npm_path()
        
        # Cấu hình token cho npm
        result = subprocess.run([npm_path, "config", "set", "//registry.npmjs.org/:_authToken", npm_token], 
                              capture_output=True, text=True, check=True)
        
        print(f"  npm token configured successfully")
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"  {Colors.RED}Failed to configure npm token: {e.stderr}{Colors.RESET}")
        return False
    except Exception as e:
        print(f"  {Colors.RED}Failed to configure npm token: {e}{Colors.RESET}")
        return False

def download_and_extract_package(npm_path, pkg_info, daily_dir, daily_log_file):
    """Hàm xử lý download và extract một package với feature criteria checking - CHẠY TUẦN TỰ"""
    pkg_version_string = f"{pkg_info['name']}@{pkg_info['version']}"
    
    try:
        # Xác định shell parameter dựa trên OS
        shell_param = platform.system() == "Windows"
        
        # Download package với token authentication
        result = subprocess.run(
            [npm_path, 'pack', pkg_version_string],
            cwd=daily_dir,
            capture_output=True,
            text=True,
            timeout=120,
            shell=shell_param
        )
        
        if result.returncode == 0:
            output = result.stdout.strip()
            tgz_files = []
            
            if output and os.path.isfile(os.path.join(daily_dir, output)):
                tgz_files = [os.path.join(daily_dir, output)]
            else:
                tgz_files = list(Path(daily_dir).glob("*.tgz"))
            
            if tgz_files:
                tgz_file = tgz_files[0]
                pkg_dir_name = f"{pkg_info['name']}-{pkg_info['version']}".replace('/', '-').replace('@', '')
                pkg_extract_dir = daily_dir / pkg_dir_name
                
                if pkg_extract_dir.exists():
                    shutil.rmtree(pkg_extract_dir)
                
                pkg_extract_dir.mkdir(exist_ok=True)
                
                # Extract package
                try:
                    with tarfile.open(tgz_file, 'r:gz') as tar:
                        tar.extractall(pkg_extract_dir)
                    
                    package_subdir = os.path.join(pkg_extract_dir, "package")
                    if os.path.exists(package_subdir):
                        for item in os.listdir(package_subdir):
                            src = os.path.join(package_subdir, item)
                            dst = os.path.join(pkg_extract_dir, item)
                            if os.path.exists(dst):
                                if os.path.isdir(dst):
                                    shutil.rmtree(dst)
                                else:
                                    os.remove(dst)
                            shutil.move(src, pkg_extract_dir)
                        os.rmdir(package_subdir)
                    
                    # KIỂM TRA FEATURE CRITERIA
                    meets_criteria, criteria_reason = meets_package_criteria(pkg_extract_dir)
                    
                    if meets_criteria:
                        # Ghi log SUCCESS với criteria
                        write_to_log(daily_log_file, "SUCCESS", pkg_version_string, f"Meets criteria: {criteria_reason}")
                        
                        # Xóa file tgz
                        try:
                            os.remove(tgz_file)
                        except:
                            pass
                        
                        return pkg_version_string, True, f"Criteria: {criteria_reason}"
                    else:
                        # Package không đạt criteria - xóa và ghi log
                        if pkg_extract_dir.exists():
                            shutil.rmtree(pkg_extract_dir)
                        write_to_log(daily_log_file, "FILTERED", pkg_version_string, f"Failed criteria: {criteria_reason}")
                        return pkg_version_string, False, f"Failed criteria: {criteria_reason}"
                    
                except Exception as e:
                    if pkg_extract_dir.exists():
                        shutil.rmtree(pkg_extract_dir)
                    # Ghi log FAILED - Extraction
                    write_to_log(daily_log_file, "FAILED", pkg_version_string, f"Extraction failed: {e}")
                    return pkg_version_string, False, f"Extraction failed: {e}"
        
        # Ghi log FAILED - Download
        error_output = result.stderr.strip()
        write_to_log(daily_log_file, "FAILED", pkg_version_string, f"Download failed: {error_output}")
        return pkg_version_string, False, f"Download failed: {error_output}"
            
    except subprocess.TimeoutExpired:
        # Ghi log FAILED - Timeout
        write_to_log(daily_log_file, "FAILED", pkg_version_string, "Timeout")
        return pkg_version_string, False, "Timeout"
    except Exception as e:
        # Ghi log ERROR
        write_to_log(daily_log_file, "ERROR", pkg_version_string, str(e))
        return pkg_version_string, False, f"Error: {e}"

def setup_colors():
    """Thiết lập màu sắc phù hợp với từng OS"""
    system = platform.system()
    if system == "Windows":
        try:
            # Kích hoạt ANSI colors trên Windows 10+
            import ctypes
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        except:
            # Fallback: không dùng màu trên Windows cũ
            class NoColors:
                GREEN = ''
                RED = ''
                YELLOW = ''
                BLUE = ''
                RESET = ''
            return NoColors()
    return Colors

def main():
    # Thiết lập colors
    Colors = setup_colors()
    
    # Đảm bảo thư mục OUTPUT_ROOT tồn tại
    OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)
    
    print(f"Running on: {platform.system()} {platform.release()}")
    print(f"Benign Dataset directory: {OUTPUT_ROOT}")
    print("--- Start collecting BENIGN NPM packages from npm registry ---")
    print("--- Press Ctrl+C to stop ---")
    
    # Hiển thị token status
    npm_token = get_npm_token()
    if npm_token:
        print(f"  {Colors.GREEN}NPM token detected - using authenticated access{Colors.RESET}")
    else:
        print(f"  {Colors.YELLOW}No NPM token provided - using public API access (rate limits may apply){Colors.RESET}")
    
    # Hiển thị feature criteria configuration
    print(f"\n{Colors.BLUE}=== RESEARCH FEATURE CRITERIA CONFIGURATION ==={Colors.RESET}")
    print(f"Size: {PackageCriteria.SIZE['MIN_SIZE_KB']}KB - {PackageCriteria.SIZE['MAX_SIZE_MB']}MB")
    print(f"Content: Min {PackageCriteria.CONTENT['MIN_FILES']} files, Required: {PackageCriteria.CONTENT['REQUIRED_FILES']}")
    print(f"Metadata: Valid JSON, Main/Index.js, Semantic Versioning")
    print(f"{Colors.BLUE}================================================={Colors.RESET}\n")
    
    try:
        npm_path = find_npm_path()
        print(f"Using npm at: {npm_path}")
    except FileNotFoundError as e:
        print(f"ERROR: {e}")
        return
    
    # Cấu hình npm token
    if not setup_npm_token():
        print("  WARNING: Continuing without npm token configuration")
    
    while True:
        total_existing_success = count_total_successful_packages()
        
        print("------------------------------------------------------------")
        print(f"Start collecting at: {datetime.now()}")
        print(f"Total packages in dataset: {total_existing_success}/{MAX_PACKAGES_TOTAL}")
        
        if total_existing_success >= MAX_PACKAGES_TOTAL:
            print(f"  {Colors.GREEN}TARGET ACHIEVED: {total_existing_success}/{MAX_PACKAGES_TOTAL} packages collected!{Colors.RESET}")
            print(f"  {Colors.GREEN}Collection completed. Exiting...{Colors.RESET}")
            break
        
        remaining_target = MAX_PACKAGES_TOTAL - total_existing_success
        print(f"Remaining target: {remaining_target} packages")
        
        current_date = datetime.now().strftime("%Y-%m-%d")
        daily_dir = OUTPUT_ROOT / current_date
        daily_log_file = OUTPUT_ROOT / f"{current_date}.log"
        summary_file = OUTPUT_ROOT / f"{current_date}_summary.txt"
        
        print(f"Working at folder: '{daily_dir}'")
        print(f"Summary Report: '{summary_file}'")
        
        daily_dir.mkdir(parents=True, exist_ok=True)
        daily_log_file.touch(exist_ok=True)
        
        successful_downloads = 0
        filtered_packages = 0
        failed_downloads = 0
            
        try:
            # Lấy nhiều packages hơn để đảm bảo đủ sau khi lọc
            packages_to_fetch = min(remaining_target * 3, 5000)
            print(f"  Fetching {packages_to_fetch} popular packages from npm registry...")
            
            packages_data = get_popular_packages(packages_to_fetch, days_back=30)
            
            if not packages_data:
                print("  Not found any popular packages.")
            else:
                print(f"  Found {len(packages_data)} popular packages. Getting versions...")
                
                # Lấy versions cho mỗi package
                all_versions = []
                for i, pkg_data in enumerate(packages_data):
                    if len(all_versions) >= remaining_target * 2:
                        break
                        
                    pkg_name = pkg_data['package']['name']
                    print(f"    Getting versions for {pkg_name} ({i+1}/{len(packages_data)})")
                    
                    versions = get_package_versions(pkg_name, VERSIONS_PER_PACKAGE)
                    all_versions.extend(versions)
                
                print(f"  Total versions available: {len(all_versions)}")
                
                if not all_versions:
                    print("  No versions found to download.")
                else:
                    # Đọc log để tránh xử lý lại packages đã xử lý
                    processed_packages = set()
                    if daily_log_file.exists():
                        with open(daily_log_file, 'r', encoding='utf-8') as f:
                            for line in f:
                                if ':' in line:
                                    parts = line.split(':', 3)
                                    if len(parts) >= 3:
                                        pkg_str = parts[2].strip().split(' - ')[0].strip()
                                        processed_packages.add(pkg_str)
                    
                    # Lọc versions chưa xử lý
                    new_versions = []
                    for version_info in all_versions:
                        pkg_version_string = f"{version_info['name']}@{version_info['version']}"
                        if pkg_version_string not in processed_packages:
                            new_versions.append((version_info, pkg_version_string))
                    
                    if not new_versions:
                        print("  No new versions to download.")
                    else:
                        # Giới hạn số lượng versions để xử lý
                        versions_to_process = new_versions[:remaining_target * 2]
                        print(f"  Processing {len(versions_to_process)} new versions (target: {remaining_target} successful)...")
                        print(f"  {Colors.YELLOW}Research Criteria: ACTIVE - Packages will be filtered based on feature criteria{Colors.RESET}")
                        
                        # XỬ LÝ TUẦN TỰ - LOẠI BỎ MULTITHREADING
                        for i, (version_info, pkg_version_string) in enumerate(versions_to_process):
                            if successful_downloads >= remaining_target:
                                break
                                
                            print(f"    [{i+1}/{len(versions_to_process)}] Processing: {pkg_version_string}")
                            
                            # Gọi hàm download tuần tự
                            result_pkg, success, reason_msg = download_and_extract_package(
                                npm_path, version_info, daily_dir, daily_log_file
                            )
                            
                            if success:
                                successful_downloads += 1
                                current_total_success = total_existing_success + successful_downloads
                                
                                if "Criteria" in reason_msg:
                                    print(f"      [{current_total_success:04d}/{MAX_PACKAGES_TOTAL}] {Colors.GREEN}[+]{Colors.RESET} {pkg_version_string} {Colors.BLUE}[CRITERIA]{Colors.RESET}")
                                else:
                                    print(f"      [{current_total_success:04d}/{MAX_PACKAGES_TOTAL}] {Colors.GREEN}[+]{Colors.RESET} {pkg_version_string}")
                                    
                                # Kiểm tra nếu đã đủ target TỔNG
                                if current_total_success >= MAX_PACKAGES_TOTAL:
                                    print(f"  {Colors.GREEN}TARGET REACHED: {current_total_success}/{MAX_PACKAGES_TOTAL} packages{Colors.RESET}")
                                    break
                                    
                            else:
                                if "Failed criteria" in reason_msg:
                                    filtered_packages += 1
                                    current_total_success = total_existing_success + successful_downloads
                                    print(f"      [{current_total_success:04d}/{MAX_PACKAGES_TOTAL}] {Colors.YELLOW}[FILTERED]{Colors.RESET} {pkg_version_string}")
                                else:
                                    failed_downloads += 1
                                    current_total_success = total_existing_success + successful_downloads
                                    print(f"      [{current_total_success:04d}/{MAX_PACKAGES_TOTAL}] {Colors.RED}[-]{Colors.RESET} {pkg_version_string}")

                        current_total_success = total_existing_success + successful_downloads
                        print(f"  Download summary: {successful_downloads} successful, {filtered_packages} filtered, {failed_downloads} failed")
                        print(f"  Total progress: {current_total_success}/{MAX_PACKAGES_TOTAL} packages")
                        
                        # TẠO SUMMARY REPORT
                        create_summary_report(daily_log_file, summary_file, successful_downloads, filtered_packages, failed_downloads)
                    
        except Exception as e:
            print(f"  Unexpected error: {e}")
        
        # Kiểm tra nếu đã đạt target TỔNG
        current_total_success = total_existing_success + successful_downloads
        if current_total_success >= MAX_PACKAGES_TOTAL:
            print(f"  {Colors.GREEN}TARGET ACHIEVED: {current_total_success}/{MAX_PACKAGES_TOTAL} packages collected!{Colors.RESET}")
            print(f"  {Colors.GREEN}Collection completed. Exiting...{Colors.RESET}")
            break
        else:
            print(f"  Progress: {current_total_success}/{MAX_PACKAGES_TOTAL} packages")
        
        sleep_minutes = SLEEP_INTERVAL // 60
        print(f"  Finished scanning. Continuing after {sleep_minutes} minutes...")
        time.sleep(SLEEP_INTERVAL)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n--- Collection stopped by user ---")
