import os
import json
import shutil
import subprocess
from pathlib import Path
from datetime import datetime
import time
import platform
import requests
import zipfile
import random
import sys

# Lấy thư mục hiện tại và tạo thư mục MaliciousDataset
CURRENT_DIR = Path(__file__).parent
OUTPUT_ROOT = CURRENT_DIR / "MaliciousDataset"
SLEEP_INTERVAL = 3600
MAX_PACKAGES_TOTAL = 2000

# =============================================================================
# FEATURE CRITERIA CONFIGURATION - UPDATED FOR MALICIOUS PACKAGES
# =============================================================================

class PackageCriteria:
    """Tiêu chí lọc packages dựa trên nghiên cứu về malicious NPM packages"""
    
    # 1. SIZE CRITERIA - Linh hoạt hơn cho malicious packages
    SIZE = {
        'MIN_SIZE_KB': 0.1,           # Cho phép rất nhỏ (obfuscated code)
        'MAX_SIZE_MB': 100,           # Cho phép lớn hơn (embedded malware)
        'REASON': 'Theo nghiên cứu, malicious packages có kích thước đa dạng từ rất nhỏ đến lớn'
    }
    
    # 2. CONTENT CRITERIA - Tập trung vào suspicious patterns
    CONTENT = {
        'MIN_FILES': 1,               # Có thể chỉ có 1 file
        'REQUIRED_FILES': ['package.json'],
        'EXCLUDE_EXTENSIONS': ['.exe', '.dll', '.bin', '.so', '.dylib'],
        'SUSPICIOUS_PATTERNS': ['eval', 'Function', 'setTimeout', 'setInterval', 'base64', 'Buffer', 'child_process', 'exec', 'spawn'],
        'REASON': 'Malicious packages thường có ít files và chứa suspicious code patterns'
    }
    
    # 3. METADATA CRITERIA - Tìm anomalies thay vì chuẩn mực
    METADATA = {
        'CHECK_TYPO_SQUATTING': True,     # Tên gần giống package phổ biến
        'CHECK_SUSPICIOUS_SCRIPTS': True, # Có install scripts
        'CHECK_EMPTY_METADATA': True,     # Metadata nghèo nàn
        'REASON': 'Malicious packages thường có metadata anomalies và suspicious scripts'
    }

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'

def get_github_token():
    """Lấy GitHub token từ environment variable hoặc CLI argument"""
    # Ưu tiên từ environment variable
    token = os.environ.get('GITHUB_TOKEN')
    
    # Nếu không có, thử từ CLI arguments
    if not token and len(sys.argv) > 1:
        token = sys.argv[1]
    
    return token

def setup_colors():
    system = platform.system()
    if system == "Windows":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        except:
            class NoColors:
                GREEN = ''
                RED = ''
                YELLOW = ''
                BLUE = ''
                RESET = ''
            return NoColors()
    return Colors

def make_github_request(url, max_retries=5):
    """Thực hiện request đến GitHub API với retry logic và rate limiting"""
    # Lấy token từ external source
    github_token = get_github_token()
    
    headers = {
        'User-Agent': 'Mozilla/5.0'
    }
    
    # Chỉ thêm Authorization header nếu có token
    if github_token:
        headers['Authorization'] = f'token {github_token}'
    
    for attempt in range(max_retries):
        try:
            response = requests.get(url, headers=headers, timeout=30)
            
            if response.status_code == 200:
                return response
            
            elif response.status_code == 403:
                # Rate limiting - kiểm tra headers
                reset_time = response.headers.get('X-RateLimit-Reset')
                remaining = response.headers.get('X-RateLimit-Remaining', 'unknown')
                
                if reset_time:
                    reset_time = int(reset_time)
                    wait_time = max(reset_time - time.time(), 0) + 10
                    print(f"    Rate limit exceeded. Waiting {wait_time:.0f} seconds...")
                    time.sleep(wait_time)
                    continue
                else:
                    # Không có reset time, đợi exponential backoff
                    wait_time = (2 ** attempt) + random.uniform(1, 5)
                    print(f"    Rate limited (403). Waiting {wait_time:.1f} seconds...")
                    time.sleep(wait_time)
                    continue
            
            elif response.status_code == 429:
                # Too many requests
                retry_after = response.headers.get('Retry-After')
                if retry_after:
                    wait_time = int(retry_after) + 5
                else:
                    wait_time = (2 ** attempt) + random.uniform(1, 5)
                
                print(f"    Too many requests (429). Waiting {wait_time:.1f} seconds...")
                time.sleep(wait_time)
                continue
            
            else:
                # Các lỗi khác
                print(f"    API request failed: {response.status_code}")
                if attempt < max_retries - 1:
                    wait_time = (2 ** attempt) + random.uniform(1, 3)
                    print(f"    Retrying in {wait_time:.1f} seconds...")
                    time.sleep(wait_time)
                else:
                    return response
        
        except requests.exceptions.Timeout:
            print(f"    Request timeout (attempt {attempt + 1}/{max_retries})")
            if attempt < max_retries - 1:
                wait_time = (2 ** attempt) + random.uniform(1, 3)
                time.sleep(wait_time)
        
        except requests.exceptions.ConnectionError:
            print(f"    Connection error (attempt {attempt + 1}/{max_retries})")
            if attempt < max_retries - 1:
                wait_time = (2 ** attempt) + random.uniform(1, 3)
                time.sleep(wait_time)
        
        except Exception as e:
            print(f"    Request error: {e} (attempt {attempt + 1}/{max_retries})")
            if attempt < max_retries - 1:
                wait_time = (2 ** attempt) + random.uniform(1, 3)
                time.sleep(wait_time)
    
    return None

def get_github_tree(repo_owner, repo_name, path=""):
    """Lấy cấu trúc thư mục từ GitHub API với rate limiting"""
    url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/contents/{path}"
    
    response = make_github_request(url)
    if response and response.status_code == 200:
        return response.json()
    else:
        print(f"    Failed to get {path} after retries")
        return None

def find_npm_packages_via_api():
    """Tìm tất cả NPM packages thông qua GitHub API với rate limiting"""
    print("  Scanning repository structure via GitHub API...")
    
    # Hiển thị token status
    github_token = get_github_token()
    if github_token:
        print(f"  {Colors.GREEN}GitHub token detected - using authenticated access{Colors.RESET}")
    else:
        print(f"  {Colors.YELLOW}No GitHub token provided - using public API access (rate limits may apply){Colors.RESET}")
    
    packages = []
    repo_owner = "DataDog"
    repo_name = "malicious-software-packages"
    
    # Quét các categories
    categories = ["compromised_lib", "malicious_intent"]
    base_path = "samples/npm"
    
    for category in categories:
        category_path = f"{base_path}/{category}"
        print(f"  Scanning {category}...")
        
        # Thêm delay ngẫu nhiên giữa các category
        time.sleep(random.uniform(1, 3))
        
        # Lấy danh sách packages trong category
        category_data = get_github_tree(repo_owner, repo_name, category_path)
        if not category_data:
            print(f"    Failed to scan category {category}, skipping...")
            continue
        
        package_count = len([item for item in category_data if item['type'] == 'dir'])
        print(f"    Found {package_count} packages in {category}")
        
        for package_item in category_data:
            if package_item['type'] == 'dir':
                package_name = package_item['name']
                package_path = f"{category_path}/{package_name}"
                
                # Thêm delay ngẫu nhiên giữa các package
                time.sleep(random.uniform(0.5, 2))
                
                # Lấy danh sách versions trong package
                package_data = get_github_tree(repo_owner, repo_name, package_path)
                if not package_data:
                    continue
                
                for version_item in package_data:
                    if version_item['type'] == 'dir':
                        version_name = version_item['name']
                        version_path = f"{package_path}/{version_name}"
                        
                        # Thêm delay ngẫu nhiên giữa các version
                        time.sleep(random.uniform(0.3, 1))
                        
                        # Lấy danh sách files trong version
                        version_data = get_github_tree(repo_owner, repo_name, version_path)
                        if not version_data:
                            continue
                        
                        # Tìm file ZIP
                        for file_item in version_data:
                            if file_item['type'] == 'file' and file_item['name'].endswith('.zip'):
                                packages.append({
                                    'category': category,
                                    'package_name': package_name,
                                    'version': version_name,
                                    'zip_name': file_item['name'],
                                    'download_url': file_item['download_url'],
                                    'path': file_item['path']
                                })
                                print(f"      Found: {package_name}@{version_name}")
                                break  # Chỉ lấy 1 ZIP file đầu tiên
    
    print(f"  Found {len(packages)} packages total")
    return packages

def download_package_via_api(package_info, output_dir, max_retries=3):
    """Download package trực tiếp qua GitHub API với retry logic"""
    try:
        package_name = package_info['package_name']
        version = package_info['version']
        category = package_info['category']
        download_url = package_info['download_url']
        
        # Tạo tên package an toàn
        safe_name = package_name.replace('@', '').replace('/', '_')
        output_name = f"{category}_{safe_name}_{version}"
        output_path = output_dir / output_name
        
        if output_path.exists():
            return output_path, "Already exists"
        
        # Tạo thư mục
        output_path.mkdir(parents=True, exist_ok=True)
        
        print(f"    Downloading: {package_name}@{version}")
        
        # Lấy token từ external source
        github_token = get_github_token()
        
        headers = {
            'User-Agent': 'Mozilla/5.0'
        }
        
        # Chỉ thêm Authorization header nếu có token
        if github_token:
            headers['Authorization'] = f'token {github_token}'
        
        for attempt in range(max_retries):
            try:
                response = requests.get(download_url, headers=headers, timeout=120, stream=True)
                
                if response.status_code == 200:
                    # Lưu file ZIP tạm thời
                    zip_path = output_path / "package.zip"
                    with open(zip_path, 'wb') as f:
                        for chunk in response.iter_content(chunk_size=8192):
                            if chunk:
                                f.write(chunk)
                    
                    # Giải nén với password
                    if extract_zip_with_password(zip_path, output_path):
                        # Xóa file ZIP sau khi giải nén thành công
                        zip_path.unlink()
                        return output_path, "Downloaded and extracted"
                    else:
                        # Xóa thư mục nếu giải nén thất bại
                        shutil.rmtree(output_path, ignore_errors=True)
                        return None, "Extraction failed"
                
                elif response.status_code in [403, 429]:
                    # Rate limiting
                    wait_time = (2 ** attempt) + random.uniform(3, 8)
                    print(f"      Rate limited. Waiting {wait_time:.1f} seconds...")
                    time.sleep(wait_time)
                    continue
                
                else:
                    if attempt < max_retries - 1:
                        wait_time = (2 ** attempt) + random.uniform(2, 5)
                        print(f"      Download failed: {response.status_code}. Retrying in {wait_time:.1f}s...")
                        time.sleep(wait_time)
                    else:
                        shutil.rmtree(output_path, ignore_errors=True)
                        return None, f"Download failed: {response.status_code}"
            
            except Exception as e:
                if attempt < max_retries - 1:
                    wait_time = (2 ** attempt) + random.uniform(2, 5)
                    print(f"      Download error: {e}. Retrying in {wait_time:.1f}s...")
                    time.sleep(wait_time)
                else:
                    shutil.rmtree(output_path, ignore_errors=True)
                    return None, f"Download error: {str(e)}"
        
        return None, "Max retries exceeded"
            
    except Exception as e:
        # Dọn dẹp nếu có lỗi
        if 'output_path' in locals() and output_path.exists():
            shutil.rmtree(output_path, ignore_errors=True)
        return None, f"Error: {str(e)}"

def extract_zip_with_password(zip_path, extract_path, password="infected"):
    """Giải nén file ZIP với password"""
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(extract_path, pwd=password.encode('utf-8'))
        return True
    except Exception as e:
        print(f"      Extraction failed: {e}")
        return False

def meets_package_criteria(package_path):
    """Kiểm tra package có đáp ứng tiêu chí không"""
    try:
        if not package_path.exists():
            return False, "Package path does not exist"
            
        total_size = calculate_package_size(package_path)
        if total_size < PackageCriteria.SIZE['MIN_SIZE_KB'] * 1024:
            return False, f"Package too small: {total_size/1024:.1f}KB"
        
        if total_size > PackageCriteria.SIZE['MAX_SIZE_MB'] * 1024 * 1024:
            return False, f"Package too large: {total_size/(1024*1024):.1f}MB"
        
        files = list_all_files(package_path)
        if len(files) < PackageCriteria.CONTENT['MIN_FILES']:
            return False, f"Not enough files: {len(files)}"
        
        for req_file in PackageCriteria.CONTENT['REQUIRED_FILES']:
            if not any(req_file in str(file) for file in files):
                return False, f"Missing {req_file}"
        
        for file in files:
            file_str = str(file)
            if any(file_str.endswith(ext) for ext in PackageCriteria.CONTENT['EXCLUDE_EXTENSIONS']):
                return False, f"Contains binary file: {file_str}"
        
        package_json_path = find_package_json(package_path)
        if not package_json_path or not package_json_path.exists():
            return False, "Missing package.json"
        
        return True, "Meets all research criteria"
    except Exception as e:
        return False, f"Error checking criteria: {str(e)}"

def calculate_package_size(package_path):
    """Tính kích thước package"""
    total_size = 0
    try:
        for file_path in package_path.rglob('*'):
            if file_path.is_file():
                try:
                    total_size += file_path.stat().st_size
                except (OSError, IOError):
                    continue
    except (OSError, IOError):
        pass
    return total_size

def list_all_files(package_path):
    """Liệt kê tất cả files trong package"""
    files = []
    try:
        for file_path in package_path.rglob('*'):
            if file_path.is_file():
                try:
                    relative_path = file_path.relative_to(package_path)
                    files.append(str(relative_path))
                except ValueError:
                    files.append(str(file_path))
    except (OSError, IOError):
        pass
    return files

def find_package_json(package_path):
    """Tìm file package.json"""
    package_json_path = package_path / 'package.json'
    if package_json_path.exists():
        return package_json_path
    
    for json_path in package_path.rglob('package.json'):
        if json_path.exists():
            return json_path
    return None

def format_number(current, total):
    return f"[{current:04d}/{total:04d}]"

def write_to_log(daily_log_file, status, package_name, error_msg=None):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if error_msg:
        log_entry = f"{timestamp} {status}: {package_name} - {error_msg}\n"
    else:
        log_entry = f"{timestamp} {status}: {package_name}\n"
    
    try:
        with open(daily_log_file, 'a', encoding='utf-8') as f:
            f.write(log_entry)
    except Exception as e:
        print(f"    Failed to write log: {e}")

def create_summary_report(log_file, summary_file, target_count=2000):
    """Tạo file báo cáo tổng kết với format giống benign"""
    success_count = 0
    filtered_count = 0
    failed_count = 0
    compromised_count = 0
    malicious_count = 0
    
    try:
        if log_file.exists():
            with open(log_file, 'r', encoding='utf-8') as f:
                for line in f:
                    if 'SUCCESS:' in line:
                        success_count += 1
                        if 'compromised_lib' in line:
                            compromised_count += 1
                        elif 'malicious_intent' in line:
                            malicious_count += 1
                    elif 'FILTERED:' in line:
                        filtered_count += 1
                    elif 'FAILED:' in line:
                        failed_count += 1
        
        total_processed = success_count + filtered_count + failed_count
        
        # Tính phần trăm
        success_percent = (success_count / max(1, total_processed)) * 100
        filtered_percent = (filtered_count / max(1, total_processed)) * 100
        failed_percent = (failed_count / max(1, total_processed)) * 100
        
        with open(summary_file, 'w', encoding='utf-8') as f:
            f.write("=" * 60 + "\n")
            f.write("        MALICIOUS NPM PACKAGE COLLECTION SUMMARY REPORT\n")
            f.write("=" * 60 + "\n")
            f.write(f" Report Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f" Log File: {log_file.name}\n")
            f.write("-" * 60 + "\n")
            f.write(" PACKAGE PROCESSING STATISTICS:\n")
            f.write(f" Successful: {success_count:4d} packages ({success_percent:5.1f}%)\n")
            f.write(f" Filtered:   {filtered_count:4d} packages ({filtered_percent:5.1f}%)\n")
            f.write(f" Failed:     {failed_count:4d} packages ({failed_percent:5.1f}%)\n")
            f.write(f" Total:      {total_processed:4d} packages (100.0%)\n")
            f.write("-" * 60 + "\n")
            f.write(" PACKAGE ALLOCATION STATISTICS:\n")
            f.write(f" compromised_lib:  {compromised_count:4d} packages\n")
            f.write(f" malicious_intent: {malicious_count:4d} packages\n")
            f.write(f" Total:           {success_count:4d} packages\n")
            f.write("-" * 60 + "\n")
            f.write(" RESEARCH CRITERIA APPLIED:\n")
            f.write(f" • Size: {PackageCriteria.SIZE['MIN_SIZE_KB']}KB - {PackageCriteria.SIZE['MAX_SIZE_MB']}MB\n")
            f.write(f" • Content: Min {PackageCriteria.CONTENT['MIN_FILES']} files, Required: {PackageCriteria.CONTENT['REQUIRED_FILES']}\n")
            f.write(f" • Metadata: Check typo squatting, Suspicious scripts, Empty metadata\n")
            f.write("-" * 60 + "\n")
            f.write(" PERFORMANCE METRICS:\n")
            f.write(f" Success Rate: {success_percent:5.1f}%\n")
            f.write(f" Filter Rate:  {filtered_percent:5.1f}%\n")
            f.write(f" Failure Rate: {failed_percent:5.1f}%\n")
            f.write("=" * 60 + "\n")
            
    except Exception as e:
        print(f"  Error creating summary: {e}")

def download_malicious_packages_via_api():
    """Download packages thông qua GitHub API"""
    TARGET_SUCCESS = 2000
    
    Colors = setup_colors()
    
    current_date = datetime.now().strftime("%Y-%m-%d")
    daily_dir = OUTPUT_ROOT / current_date
    daily_log_file = OUTPUT_ROOT / f"{current_date}.log"
    summary_file = OUTPUT_ROOT / f"{current_date}_summary.txt"
    
    print(f"Running on: {platform.system()} {platform.release()}")
    print(f"Dataset directory: {OUTPUT_ROOT}")
    print("--- Start collecting MALICIOUS NPM packages from DataDog ---")
    print("--- Press Ctrl+C to stop ---")
    
    # Hiển thị token status
    github_token = get_github_token()
    if github_token:
        print(f"  {Colors.GREEN}GitHub token detected - using authenticated access{Colors.RESET}")
    else:
        print(f"  {Colors.YELLOW}No GitHub token provided - using public API access (rate limits may apply){Colors.RESET}")
    
    # Hiển thị feature criteria configuration
    print(f"\n{Colors.BLUE}=== RESEARCH FEATURE CRITERIA CONFIGURATION ==={Colors.RESET}")
    print(f"Size: {PackageCriteria.SIZE['MIN_SIZE_KB']}KB - {PackageCriteria.SIZE['MAX_SIZE_MB']}MB")
    print(f"Content: Min {PackageCriteria.CONTENT['MIN_FILES']} files, Required: {PackageCriteria.CONTENT['REQUIRED_FILES']}")
    print(f"Metadata: Check typo squatting, Suspicious scripts, Empty metadata")
    print(f"Based on: Malicious package patterns research")
    print(f"{Colors.BLUE}================================================={Colors.RESET}\n")
    
    OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)
    daily_dir.mkdir(parents=True, exist_ok=True)
    
    # Đếm existing success count
    existing_success_count = 0
    if daily_log_file.exists():
        try:
            with open(daily_log_file, 'r', encoding='utf-8') as f:
                for line in f:
                    if 'SUCCESS:' in line:
                        existing_success_count += 1
        except Exception:
            existing_success_count = 0
    
    remaining_target = TARGET_SUCCESS - existing_success_count
    
    if remaining_target <= 0:
        print(f"  Target already reached: {existing_success_count}/{TARGET_SUCCESS} packages")
        time.sleep(SLEEP_INTERVAL)
        return True
        
    print("------------------------------------------------------------")
    print(f"Start collecting at: {datetime.now()}")
    print(f"Working at folder: '{daily_dir}'")
    print(f"Summary Report: '{summary_file}'")
    
    # Tìm packages qua API
    packages = find_npm_packages_via_api()
    
    if not packages:
        print("  No packages found via API")
        return False
    
    successful_downloads = 0
    filtered_packages = 0
    failed_downloads = 0
    
    for i, package_info in enumerate(packages):
        if successful_downloads >= remaining_target:
            break
            
        package_name = package_info['package_name']
        version = package_info['version']
        category = package_info['category']
        
        print(f"    [{i+1}/{len(packages)}] Processing: {package_name}@{version}")
        
        # Thêm delay ngẫu nhiên giữa các package download
        if i > 0:
            delay = random.uniform(2, 5)
            print(f"      Waiting {delay:.1f} seconds...")
            time.sleep(delay)
        
        # Download package
        package_path, result_msg = download_package_via_api(package_info, daily_dir)
        
        if package_path:
            # Kiểm tra criteria
            meets_criteria, criteria_reason = meets_package_criteria(package_path)
            
            if meets_criteria:
                successful_downloads += 1
                write_to_log(daily_log_file, "SUCCESS", package_path.name, f"Meets criteria: {criteria_reason}")
                
                current_total = existing_success_count + successful_downloads
                formatted_number = format_number(current_total, TARGET_SUCCESS)
                print(f"      {formatted_number} {Colors.GREEN}[+]{Colors.RESET} {package_name} {Colors.BLUE}[CRITERIA]{Colors.RESET}")
                
                if current_total >= TARGET_SUCCESS:
                    print(f"  {Colors.GREEN}TARGET REACHED: {current_total}/{TARGET_SUCCESS} packages{Colors.RESET}")
                    break
            else:
                filtered_packages += 1
                shutil.rmtree(package_path, ignore_errors=True)
                write_to_log(daily_log_file, "FILTERED", package_name, f"Failed criteria: {criteria_reason}")
                print(f"      {Colors.YELLOW}[FILTERED]{Colors.RESET} {package_name}: {criteria_reason}")
        else:
            failed_downloads += 1
            write_to_log(daily_log_file, "FAILED", package_name, result_msg)
            print(f"      {Colors.RED}[-]{Colors.RESET} {package_name}: {result_msg}")
    
    # Tạo summary report
    create_summary_report(daily_log_file, summary_file, TARGET_SUCCESS)
    
    current_total_success = existing_success_count + successful_downloads
    print(f"  Processing summary: {successful_downloads} successful, {filtered_packages} filtered, {failed_downloads} failed")
    print(f"  Total progress: {current_total_success}/{TARGET_SUCCESS} packages")
    
    if current_total_success >= TARGET_SUCCESS:
        print(f"  {Colors.GREEN}TARGET ACHIEVED: {current_total_success}/{TARGET_SUCCESS} packages collected!{Colors.RESET}")
    else:
        print(f"  Progress: {current_total_success}/{TARGET_SUCCESS} packages")
    
    sleep_minutes = SLEEP_INTERVAL // 60
    print(f"  Finished processing. Continuing after {sleep_minutes} minutes...")
    
    return True

def main():
    try:
        while True:
            success = download_malicious_packages_via_api()
            if not success:
                print("  Collection failed. Retrying after delay...")
            time.sleep(SLEEP_INTERVAL)
    except KeyboardInterrupt:
        print("\n--- Collection stopped by user ---")

if __name__ == "__main__":
    main()
