import os
import json
import math
import hashlib
import csv
import re
from pathlib import Path
from collections import Counter
from datetime import datetime
from packaging.version import Version, InvalidVersion

# Cần tải tree sitter và language binding: pip install tree-sitter & pip install tree-sitter-javascript
try:
    from tree_sitter import Language, Parser
    import tree_sitter_javascript as tsjs
    TREE_SITTER_AVAILABLE = True
    JS_LANGUAGE = Language(tsjs.language())
except ImportError:
    TREE_SITTER_AVAILABLE = False
    print("Warning: Tree-sitter not available. Some advanced features will be disabled.")

class AdvancedFeatureExtractor:
    """Optimized feature extractor based on Amalfi research with version change analysis"""
    
    def __init__(self):
        self.suspicious_packages = ["request", "axios", "node-fetch", "http", "https", "fs-extra", 
                                   "shelljs", "child_process", "net", "os", "exec", "spawn"]
        
    def calculate_entropy(self, data):
        """Calculate the Shannon entropy of a string."""
        if not data:
            return 0
        counter = Counter(data)
        length = len(data)
        return -sum((count / length) * math.log2(count / length) for count in counter.values())

    def read_file(self, filepath):
        """Read a file and return its content as a string."""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except Exception as e:
            return ""

    def detect_binary(self, filepath):
        """Detect if a file is a binary file."""
        try:
            with open(filepath, 'rb') as f:
                chunk = f.read(1024)
                return any(byte > 127 for byte in chunk)
        except Exception:
            return False

    def extract_network_features(self, content):
        """Extract network-related features including URLs and IPs"""
        features = {
            "suspicious_urls": 0,
            "ip_addresses": 0,
            "data_exfiltration_patterns": 0
        }
        
        # URL patterns
        url_pattern = re.compile(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+')
        ip_pattern = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
        
        features["suspicious_urls"] = len(url_pattern.findall(content))
        features["ip_addresses"] = len(ip_pattern.findall(content))
        
        # Data exfiltration patterns
        exfil_patterns = [
            r'\.send\(.*\)',
            r'\.post\(.*\)',
            r'XMLHttpRequest',
            r'fetch\(',
            r'\.request\('
        ]
        
        for pattern in exfil_patterns:
            features["data_exfiltration_patterns"] += len(re.findall(pattern, content, re.IGNORECASE))
        
        return features

    def extract_pii_patterns_ast(self, js_code):
        """Use AST to detect actual PII access patterns"""
        if not TREE_SITTER_AVAILABLE or not js_code:
            return {
                "password_access": 0,
                "cookie_access": 0,
                "env_secrets": 0
            }
        
        pii_features = {
            "password_access": 0,
            "cookie_access": 0,
            "env_secrets": 0
        }
        
        try:
            parser = Parser(JS_LANGUAGE)
            tree = parser.parse(bytes(js_code, "utf8"))
            root_node = tree.root_node
            
            def traverse_pii(node):
                if node.type == "member_expression":
                    # Check for document.cookie
                    if node.text.decode("utf8") == "document.cookie":
                        pii_features["cookie_access"] += 1
                    
                    # Check for process.env
                    if "process.env" in node.text.decode("utf8"):
                        pii_features["env_secrets"] += 1
                
                # Check for password-related patterns
                if node.type == "property_identifier":
                    prop_name = node.text.decode("utf8").lower()
                    if "password" in prop_name or "passwd" in prop_name:
                        pii_features["password_access"] += 1
                
                for child in node.children:
                    traverse_pii(child)
            
            traverse_pii(root_node)
            return pii_features
            
        except Exception:
            return pii_features

    def extract_sensitive_code_features(self, js_code):
        """Enhanced feature extraction using Tree-sitter for sensitive JavaScript patterns"""
        if not TREE_SITTER_AVAILABLE or not js_code:
            return {
                "system_command_usage": 0,
                "file_access": 0,
                "env_variable_access": 0,
                "network_access": 0,
                "crypto_usage": 0,
                "data_encoding": 0,
                "dynamic_code_generation": 0,
                "os_access": 0
            }

        try:
            parser = Parser(JS_LANGUAGE)
            tree = parser.parse(bytes(js_code, "utf8"))
            root_node = tree.root_node

            features = {
                "system_command_usage": 0,
                "file_access": 0,
                "env_variable_access": 0,
                "network_access": 0,
                "crypto_usage": 0,
                "data_encoding": 0,
                "dynamic_code_generation": 0,
                "os_access": 0
            }

            def traverse(node):
                if node.type == "call_expression":
                    func_node = node.child_by_field_name("function")
                    if func_node:
                        func_name = func_node.text.decode("utf8")
                        
                        # File system access
                        if "fs." in func_name and any(op in func_name for op in ["read", "write", "unlink", "copy", "move"]):
                            features["file_access"] += 1
                        
                        # Environment variables
                        elif "process.env" in func_name:
                            features["env_variable_access"] += 1
                        
                        # System commands
                        elif any(cmd in func_name for cmd in ["exec", "spawn", "execSync", "spawnSync"]):
                            features["system_command_usage"] += 1
                        
                        # Network access
                        elif any(net in func_name for net in ["http.", "https.", "fetch", "request", "net."]):
                            features["network_access"] += 1
                        
                        # Crypto functionality
                        elif "crypto." in func_name or "Crypto" in func_name:
                            features["crypto_usage"] += 1
                        
                        # OS access
                        elif "os." in func_name:
                            features["os_access"] += 1
                        
                        # Dynamic code generation
                        elif any(dyn in func_name for dyn in ["eval", "Function", "setTimeout", "setInterval", "setImmediate"]):
                            features["dynamic_code_generation"] += 1
                        
                        # Data encoding
                        elif any(enc in func_name for enc in ["encodeURIComponent", "decodeURIComponent", "btoa", "atob", "Buffer"]):
                            features["data_encoding"] += 1

                for child in node.children:
                    traverse(child)

            traverse(root_node)
            return features
        except Exception:
            return {
                "system_command_usage": 0,
                "file_access": 0,
                "env_variable_access": 0,
                "network_access": 0,
                "crypto_usage": 0,
                "data_encoding": 0,
                "dynamic_code_generation": 0,
                "os_access": 0
            }

    def analyze_dependencies(self, package_data):
        """Analyze dependency patterns for suspicious packages"""
        features = {
            "suspicious_dependencies_count": 0,
            "dependencies_ratio": 0,
            "dev_dependencies_ratio": 0,
            "total_dependencies_count": 0
        }
        
        dependencies = package_data.get('dependencies', {})
        dev_dependencies = package_data.get('devDependencies', {})
        
        # Count suspicious dependencies
        for dep in dependencies:
            if any(suspicious in dep.lower() for suspicious in self.suspicious_packages):
                features["suspicious_dependencies_count"] += 1
        
        # Calculate ratios
        total_deps = len(dependencies) + len(dev_dependencies)
        features["total_dependencies_count"] = total_deps
        
        if total_deps > 0:
            features["dependencies_ratio"] = len(dependencies) / total_deps
            features["dev_dependencies_ratio"] = len(dev_dependencies) / total_deps
        
        return features

    def analyze_file_structure(self, package_path):
        """Detect anomalous file structures"""
        features = {
            "js_files_in_root": 0,
            "hidden_files": 0,
            "max_file_size_kb": 0,
            "avg_file_size_kb": 0
        }
        
        files = self.list_all_files(package_path)
        file_sizes = []
        
        for file_path in package_path.rglob('*'):
            if file_path.is_file():
                try:
                    # File size analysis
                    file_size = file_path.stat().st_size
                    file_sizes.append(file_size)
                    
                    # File location analysis
                    relative_path = str(file_path.relative_to(package_path))
                    if relative_path.endswith('.js') and '/' not in relative_path:
                        features["js_files_in_root"] += 1
                    if relative_path.startswith('.'):
                        features["hidden_files"] += 1
                        
                except Exception:
                    continue
        
        # Calculate file size statistics
        if file_sizes:
            features["max_file_size_kb"] = max(file_sizes) / 1024
            features["avg_file_size_kb"] = sum(file_sizes) / len(file_sizes) / 1024
        
        return features

    def extract_version_analysis_features(self, package_path, package_data):
        """Extract version change features based on Amalfi research"""
        features = {
            # Version type analysis
            "is_major_update": 0,
            "is_minor_update": 0,
            "is_patch_update": 0,
            "is_first_version": 1,  # Default assumption
            
            # Temporal analysis from directory structure
            "has_other_versions_today": 0,
            "total_versions_today": 1,
            "is_rapid_update": 0,
            
            # Version metadata
            "has_prerelease": 0
        }
        
        # Analyze semantic versioning
        version_str = package_data.get('version', '0.0.0')
        try:
            version = Version(version_str)
            
            # Check for pre-release versions
            if version.pre:
                features["has_prerelease"] = 1
            
            # Simple version type analysis
            if version.major > 0 and version_str.startswith('1.0.0'):
                features["is_first_version"] = 1
            else:
                features["is_first_version"] = 0
                
        except (InvalidVersion, AttributeError):
            # Fallback for invalid versions
            pass
        
        # Analyze directory structure for version patterns
        date_dir = package_path.parent
        if date_dir.exists():
            sibling_packages = [d for d in date_dir.iterdir() if d.is_dir() and d != package_path]
            features["total_versions_today"] = len(sibling_packages) + 1
            features["has_other_versions_today"] = 1 if len(sibling_packages) > 0 else 0
            
            # Detect rapid updates (multiple versions same day)
            if len(sibling_packages) >= 2:
                features["is_rapid_update"] = 1
        
        return features

    def extract_advanced_features(self, package_dir):
        """Extract advanced features using Tree-sitter and entropy analysis"""
        features = {
            # Entropy features
            "max_entropy": 0,
            "avg_entropy": 0,
            "minified_files": 0,
            "binary_files": 0,
            
            # Security features
            "system_command_usage": 0,
            "file_access": 0, 
            "env_variable_access": 0,
            "network_access": 0,
            "crypto_usage": 0,
            "data_encoding": 0,
            "dynamic_code_generation": 0,
            "os_access": 0,
            
            # Network features
            "suspicious_urls": 0,
            "ip_addresses": 0,
            "data_exfiltration_patterns": 0,
            
            # PII AST features
            "password_access": 0,
            "cookie_access": 0,
            "env_secrets": 0,
        }

        entropies = []
        total_files = 0

        for root, _, files in os.walk(package_dir):
            for file in files:
                filepath = os.path.join(root, file)
                total_files += 1
                
                try:
                    if self.detect_binary(filepath):
                        features["binary_files"] += 1
                        continue

                    content = self.read_file(filepath)
                    if content:
                        entropy = self.calculate_entropy(content)
                        entropies.append(entropy)

                        # Minified file detection
                        if len(content.splitlines()) < 5 and len(content) > 500:
                            features["minified_files"] += 1

                        # JavaScript/TypeScript code analysis
                        if file.endswith(('.js', '.ts', '.jsx', '.tsx')):
                            js_features = self.extract_sensitive_code_features(content)
                            for key, value in js_features.items():
                                features[key] += value
                            
                            # Enhanced PII detection using AST
                            pii_ast_features = self.extract_pii_patterns_ast(content)
                            for key, value in pii_ast_features.items():
                                features[key] += value
                            
                            # Network feature extraction
                            network_features = self.extract_network_features(content)
                            for key, value in network_features.items():
                                features[key] += value

                except Exception:
                    continue

        # Calculate entropy statistics
        if entropies:
            features["max_entropy"] = max(entropies)
            features["avg_entropy"] = sum(entropies) / len(entropies)

        return features

    def extract_basic_features(self, package_path):
        """Extract basic structural features"""
        features = {}
        
        try:
            # 1. Structural Features
            files = self.list_all_files(package_path)
            features['file_count'] = len(files)
            features['total_size_kb'] = self.calculate_package_size(package_path) / 1024
            features['has_node_modules'] = any('node_modules' in str(file) for file in files)
            
            # 2. File Type Distribution
            file_extensions = {}
            for file in files:
                ext = Path(file).suffix.lower()
                file_extensions[ext] = file_extensions.get(ext, 0) + 1
            
            features['js_file_ratio'] = file_extensions.get('.js', 0) / max(1, len(files))
            features['json_file_ratio'] = file_extensions.get('.json', 0) / max(1, len(files))
            
            # 3. Metadata Features
            package_json_path = self.find_package_json(package_path)
            features.update({
                'dependencies_count': 0,
                'dev_dependencies_count': 0,
                'scripts_count': 0,
                'has_preinstall': 0,
                'has_postinstall': 0,
                'has_preuninstall': 0,
            })

            package_data = {}
            if package_json_path and package_json_path.exists():
                try:
                    with open(package_json_path, 'r', encoding='utf-8', errors='ignore') as f:
                        package_data = json.load(f)
                    
                    # Override với giá trị thực
                    features['dependencies_count'] = len(package_data.get('dependencies', {}))
                    features['dev_dependencies_count'] = len(package_data.get('devDependencies', {}))
                    features['scripts_count'] = len(package_data.get('scripts', {}))
                    features['has_preinstall'] = 1 if 'preinstall' in package_data.get('scripts', {}) else 0
                    features['has_postinstall'] = 1 if 'postinstall' in package_data.get('scripts', {}) else 0
                    features['has_preuninstall'] = 1 if 'preuninstall' in package_data.get('scripts', {}) else 0
                    
                except (json.JSONDecodeError, UnicodeDecodeError) as e:
                    print(f"Error parsing package.json: {e}")
            
            # 4. Content Features
            features['has_readme'] = 1 if any('readme' in str(file).lower() for file in files) else 0
            features['has_license'] = 1 if any('license' in str(file).lower() for file in files) else 0
            
            # 5. Dependency Analysis Features
            dependency_features = self.analyze_dependencies(package_data)
            features.update(dependency_features)
            
            # 6. File Structure Analysis
            file_structure_features = self.analyze_file_structure(package_path)
            features.update(file_structure_features)
            
            # 7. Version Analysis Features (QUAN TRỌNG - từ ý bạn)
            version_features = self.extract_version_analysis_features(package_path, package_data)
            features.update(version_features)
            
        except Exception as e:
            print(f"Error extracting basic features: {e}")
            # Set comprehensive default values
            features = {
                'file_count': 0, 'total_size_kb': 0, 'has_node_modules': 0,
                'js_file_ratio': 0, 'json_file_ratio': 0,
                'dependencies_count': 0, 'dev_dependencies_count': 0, 'scripts_count': 0,
                'has_preinstall': 0, 'has_postinstall': 0, 'has_preuninstall': 0,
                'has_readme': 0, 'has_license': 0,
                'suspicious_dependencies_count': 0, 'dependencies_ratio': 0, 
                'dev_dependencies_ratio': 0, 'total_dependencies_count': 0,
                'js_files_in_root': 0, 'hidden_files': 0, 'max_file_size_kb': 0,
                'avg_file_size_kb': 0, 'is_major_update': 0, 'is_minor_update': 0,
                'is_patch_update': 0, 'is_first_version': 1, 'has_other_versions_today': 0,
                'total_versions_today': 1, 'is_rapid_update': 0, 'has_prerelease': 0
            }
        
        return features

    def calculate_package_size(self, package_path):
        """Calculate total package size in bytes"""
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

    def list_all_files(self, package_path):
        """List all files in package"""
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

    def find_package_json(self, package_path):
        """Find package.json file"""
        package_json_path = package_path / 'package.json'
        if package_json_path.exists():
            return package_json_path
        
        for json_path in package_path.rglob('package.json'):
            if json_path.exists():
                return json_path
        return None

    def extract_all_features(self, package_path, package_type="unknown"):
        """Extract both basic and advanced features"""
        basic_features = self.extract_basic_features(package_path)
        advanced_features = self.extract_advanced_features(package_path)
        
        # Combine all features
        all_features = {**basic_features, **advanced_features}
        all_features['package_type'] = package_type
        all_features['collection_date'] = datetime.now().isoformat()
        all_features['analysis_timestamp'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        return all_features

def main():
    """Main function to process both Benign and Malicious datasets"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Extract features from NPM packages dataset")
    parser.add_argument("--dataset-dir", default="Dataset", help="Root dataset directory")
    parser.add_argument("--output-dir", default="Features", help="Output directory for features")
    
    args = parser.parse_args()
    
    current_dir = Path(__file__).parent
    parent_dir = current_dir.parent 
    
    dataset_dir = parent_dir / args.dataset_dir  
    output_dir = parent_dir / args.output_dir 
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Tạo 1 file CSV duy nhất
    combined_csv_path = output_dir / "features.csv"
    
    extractor = AdvancedFeatureExtractor()
    
    with open(combined_csv_path, 'w', newline='', encoding='utf-8') as combined_file:
        combined_writer = None
        processed_count = 0
        
        # Process BenignDataset
        benign_dir = dataset_dir / "BenignDataset"
        if benign_dir.exists():
            print("Processing BenignDataset...")
            for date_dir in benign_dir.iterdir():
                if date_dir.is_dir():
                    print(f"  Processing date directory: {date_dir.name}")
                    for package_dir in date_dir.iterdir():
                        if package_dir.is_dir():
                            try:
                                print(f"    Extracting features from: {package_dir.name}")
                                features = extractor.extract_all_features(package_dir, "benign")
                                
                                if combined_writer is None:
                                    combined_writer = csv.DictWriter(combined_file, fieldnames=features.keys())
                                    combined_writer.writeheader()
                                
                                combined_writer.writerow(features)
                                processed_count += 1
                                print(f"      Processed: {package_dir.name}")
                                
                            except Exception as e:
                                print(f"      Error processing {package_dir.name}: {e}")
        else:
            print(f"BenignDataset directory not found: {benign_dir}")
        
        # Process MaliciousDataset - GHI TIẾP VÀO CÙNG FILE
        malicious_dir = dataset_dir / "MaliciousDataset"
        if malicious_dir.exists():
            print("Processing MaliciousDataset...")
            for date_dir in malicious_dir.iterdir():
                if date_dir.is_dir():
                    print(f"  Processing date directory: {date_dir.name}")
                    for package_dir in date_dir.iterdir():
                        if package_dir.is_dir():
                            try:
                                print(f"    Extracting features from: {package_dir.name}")
                                features = extractor.extract_all_features(package_dir, "malicious")
                                
                                combined_writer.writerow(features)
                                processed_count += 1
                                print(f"      Processed: {package_dir.name}")
                                
                            except Exception as e:
                                print(f"      Error processing {package_dir.name}: {e}")
        else:
            print(f"MaliciousDataset directory not found: {malicious_dir}")
    
    print(f"All features saved to: {combined_csv_path}")
    print(f"Total packages processed: {processed_count}")
    print("Feature extraction completed!")

if __name__ == "__main__":
    main()
