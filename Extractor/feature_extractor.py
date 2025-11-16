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
        self.suspicious_packages = ["request", "axios", "node-fetch", "fs-extra", 
                                   "shelljs", "child_process", "exec", "spawn"]
        
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

    def extract_granular_security_patterns(self, content):
        """Extract granular security patterns based on MalPacDetector taxonomy"""
        features = {
            # File System (3 features)
            "fs_read_count": 0,
            "fs_write_count": 0,
            "fs_delete_count": 0,
            
            # Network (3 features)
            "http_request_count": 0,
            "fetch_count": 0,
            "socket_count": 0,
            
            # Process (3 features)
            "exec_count": 0,
            "spawn_count": 0,
            "fork_count": 0,
            
            # PII & Sensitive Data (3 features)
            "password_access": 0,
            "cookie_access": 0,
            "env_variable_access": 0,
            
            # Obfuscation & Malicious Patterns
            "base64_pattern_count": 0,
            "eval_usage_count": 0
        }
        
        # File System Patterns
        features["fs_read_count"] = len(re.findall(r'fs\.readFile|readFileSync', content))
        features["fs_write_count"] = len(re.findall(r'fs\.writeFile|writeFileSync', content))
        features["fs_delete_count"] = len(re.findall(r'fs\.unlink|fs\.rmdir|fs\.rm', content))
        
        # Network Patterns
        features["http_request_count"] = len(re.findall(r'http\.request|https\.request', content))
        features["fetch_count"] = len(re.findall(r'fetch\s*\(|axios\.(get|post)', content))
        features["socket_count"] = len(re.findall(r'net\.Socket|net\.connect', content))
        
        # Process Patterns
        features["exec_count"] = len(re.findall(r'exec\s*\(|execSync', content))
        features["spawn_count"] = len(re.findall(r'spawn\s*\(|spawnSync', content))
        features["fork_count"] = len(re.findall(r'child_process\.fork', content))
        
        # PII & Sensitive Data
        features["password_access"] = len(re.findall(r'password|passwd', content, re.IGNORECASE))
        features["cookie_access"] = len(re.findall(r'document\.cookie', content))
        features["env_variable_access"] = len(re.findall(r'process\.env', content))
        
        # Malicious Patterns
        features["base64_pattern_count"] = len(re.findall(r'[A-Za-z0-9+/]{20,}={0,2}', content))
        features["eval_usage_count"] = len(re.findall(r'eval\s*\(', content))
        
        return features

    def extract_pii_patterns_ast(self, js_code):
        """Use AST to detect actual PII access patterns"""
        if not TREE_SITTER_AVAILABLE or not js_code:
            return {
                "password_access": 0,
                "cookie_access": 0
            }
        
        pii_features = {
            "password_access": 0,
            "cookie_access": 0
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

    def analyze_dependencies(self, package_data):
        """Analyze dependency patterns for suspicious packages"""
        features = {
            "suspicious_dependencies_count": 0,
            "total_dependencies_count": 0
        }
        
        dependencies = package_data.get('dependencies', {})
        dev_dependencies = package_data.get('devDependencies', {})
        
        # Count suspicious dependencies
        for dep in dependencies:
            if any(suspicious in dep.lower() for suspicious in self.suspicious_packages):
                features["suspicious_dependencies_count"] += 1
        
        # Calculate total
        total_deps = len(dependencies) + len(dev_dependencies)
        features["total_dependencies_count"] = total_deps
        
        return features

    def analyze_file_structure(self, package_path):
        """Detect anomalous file structures"""
        features = {
            "js_files_in_root": 0,
            "hidden_files": 0,
            "max_file_size_kb": 0
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
        
        return features

    def extract_version_analysis_features(self, package_path, package_data):
        """Extract version change features based on Amalfi research"""
        features = {
            "is_first_version": 1,
            "has_other_versions_today": 0,
            "is_rapid_update": 0,
            "version_velocity": 0,
            "maintenance_score": 0,
            "time_between_updates": 0,
            "update_type": 0
        }
        
        # Analyze semantic versioning
        version_str = package_data.get('version', '0.0.0')
        try:
            version = Version(version_str)
            
            # Simple version type analysis
            if version.major > 0 and version_str.startswith('1.0.0'):
                features["is_first_version"] = 1
            else:
                features["is_first_version"] = 0
            
            # Update type classification
            if version.pre:  # prerelease
                features["update_type"] = 4
            elif version.micro > 0 and version_str.count('.') >= 2:  # patch
                features["update_type"] = 3
            elif version.minor > 0:  # minor
                features["update_type"] = 2
            elif version.major > 0:  # major
                features["update_type"] = 1
            else:  # first version
                features["update_type"] = 0
                
        except (InvalidVersion, AttributeError):
            # Fallback for invalid versions
            pass
        
        # Analyze directory structure for version patterns
        date_dir = package_path.parent
        if date_dir.exists():
            sibling_packages = [d for d in date_dir.iterdir() if d.is_dir() and d != package_path]
            features["has_other_versions_today"] = 1 if len(sibling_packages) > 0 else 0
            
            # Detect rapid updates (multiple versions same day)
            if len(sibling_packages) >= 2:
                features["is_rapid_update"] = 1
            
            # Version velocity
            features["version_velocity"] = min(len(sibling_packages) / 10.0, 1.0)
            
            # Maintenance score
            features["maintenance_score"] = 1.0 if len(sibling_packages) > 0 else 0.0
            
            # Time between updates (simplified - using directory count as proxy)
            features["time_between_updates"] = len(sibling_packages)
        
        return features

    def extract_install_script_features(self, package_path):
        """Extract install script analysis features - MalPacDetector's SECRET WEAPON"""
        features = {
            "has_install_command": 0,
            "base64_in_install_script": 0,
            "domain_in_install_script": 0,
            "network_in_install_script": 0,
            "process_env_in_install_script": 0,
            "file_ops_in_install_script": 0,
            "shell_exec_in_install_script": 0
        }
        
        try:
            package_json_path = self.find_package_json(package_path)
            if package_json_path and package_json_path.exists():
                with open(package_json_path, 'r', encoding='utf-8', errors='ignore') as f:
                    package_data = json.load(f)
                
                scripts = package_data.get('scripts', {})
                
                # Check for install-related scripts
                install_scripts = []
                for script_name, script_content in scripts.items():
                    if any(keyword in script_name for keyword in ['install', 'preinstall', 'postinstall']):
                        install_scripts.append(script_content)
                        features["has_install_command"] = 1
                
                # Analyze install script content
                for script_content in install_scripts:
                    features["base64_in_install_script"] += len(re.findall(r'[A-Za-z0-9+/]{20,}={0,2}', script_content))
                    features["domain_in_install_script"] += len(re.findall(r'https?://[^\s"\']+', script_content))
                    features["network_in_install_script"] += len(re.findall(r'curl|wget|fetch|http', script_content, re.IGNORECASE))
                    features["process_env_in_install_script"] += len(re.findall(r'process\.env', script_content))
                    features["file_ops_in_install_script"] += len(re.findall(r'fs\.|readFile|writeFile', script_content))
                    features["shell_exec_in_install_script"] += len(re.findall(r'exec|spawn|child_process', script_content))
                    
        except Exception as e:
            print(f"Error extracting install script features: {e}")
            
        return features

    def extract_advanced_features(self, package_dir):
        """Extract advanced features using Tree-sitter and entropy analysis"""
        features = {
            # Entropy features
            "max_entropy": 0,
            "avg_entropy": 0,
            "entropy_variance": 0,
            "minified_files": 0,
            "minified_ratio": 0,
            "obfuscation_score": 0,
            
            # Density features
            "base64_density": 0,
            "eval_density": 0
        }

        entropies = []
        total_files_analyzed = 0
        total_js_files = 0
        minified_files = 0
        total_base64_count = 0
        total_eval_count = 0

        for root, _, files in os.walk(package_dir):
            for file in files:
                filepath = os.path.join(root, file)
                
                try:
                    content = self.read_file(filepath)
                    if content and len(content) > 100:
                        entropy = self.calculate_entropy(content)
                        entropies.append(entropy)
                        total_files_analyzed += 1

                        # Minified file detection
                        if len(content.splitlines()) < 5 and len(content) > 500:
                            minified_files += 1

                        # JavaScript/TypeScript code analysis
                        if file.endswith(('.js', '.ts', '.jsx', '.tsx')):
                            total_js_files += 1
                            
                            # Extract granular security patterns
                            security_features = self.extract_granular_security_patterns(content)
                            for key, value in security_features.items():
                                if key in features:
                                    features[key] += value
                                else:
                                    features[key] = value
                            
                            # Track totals for density calculation
                            total_base64_count += security_features["base64_pattern_count"]
                            total_eval_count += security_features["eval_usage_count"]
                            
                            # Enhanced PII detection using AST
                            pii_ast_features = self.extract_pii_patterns_ast(content)
                            for key, value in pii_ast_features.items():
                                features[key] += value

                except Exception:
                    continue

        # Calculate entropy statistics
        if entropies:
            features["max_entropy"] = max(entropies)
            features["avg_entropy"] = sum(entropies) / len(entropies)
            if len(entropies) > 1:
                features["entropy_variance"] = sum((x - features["avg_entropy"]) ** 2 for x in entropies) / len(entropies)

        # Calculate ratios and densities
        if total_js_files > 0:
            features["minified_ratio"] = minified_files / total_js_files
            features["base64_density"] = total_base64_count / total_js_files
            features["eval_density"] = total_eval_count / total_js_files
        
        # Calculate obfuscation score (composite metric)
        features["obfuscation_score"] = min(
            (features["minified_ratio"] * 0.4 + 
             features["base64_density"] * 0.3 + 
             features["eval_density"] * 0.3) * 10, 1.0
        )

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
            
            # 3. Metadata Features
            package_json_path = self.find_package_json(package_path)
            features.update({
                'dependencies_count': 0,
                'scripts_count': 0,
                'has_preinstall': 0,
                'has_postinstall': 0,
                'has_install_script': 0
            })

            package_data = {}
            if package_json_path and package_json_path.exists():
                try:
                    with open(package_json_path, 'r', encoding='utf-8', errors='ignore') as f:
                        package_data = json.load(f)
                    
                    features['dependencies_count'] = len(package_data.get('dependencies', {}))
                    features['scripts_count'] = len(package_data.get('scripts', {}))
                    features['has_preinstall'] = 1 if 'preinstall' in package_data.get('scripts', {}) else 0
                    features['has_postinstall'] = 1 if 'postinstall' in package_data.get('scripts', {}) else 0
                    features['has_install_script'] = 1 if 'install' in package_data.get('scripts', {}) else 0
                    
                except (json.JSONDecodeError, UnicodeDecodeError) as e:
                    print(f"Error parsing package.json: {e}")
            
            # 4. Content Features
            features['has_readme'] = 1 if any('readme' in str(file).lower() for file in files) else 0
            
            # 5. Dependency Analysis Features
            dependency_features = self.analyze_dependencies(package_data)
            features.update(dependency_features)
            
            # 6. File Structure Analysis
            file_structure_features = self.analyze_file_structure(package_path)
            features.update(file_structure_features)
            
            # 7. Version Analysis Features
            version_features = self.extract_version_analysis_features(package_path, package_data)
            features.update(version_features)
            
        except Exception as e:
            print(f"Error extracting basic features: {e}")
            features = self._get_default_features()
        
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

    def _get_default_features(self):
        """Return default feature set with 52 features"""
        return {
            # Structural Features (8)
            'file_count': 0, 'total_size_kb': 0, 'has_node_modules': 0,
            'js_file_ratio': 0, 'js_files_in_root': 0, 'hidden_files': 0,
            'max_file_size_kb': 0, 'dir_count': 0,
            
            # Package Metadata (7)
            'dependencies_count': 0, 'scripts_count': 0, 'has_preinstall': 0,
            'has_postinstall': 0, 'has_install_script': 0,
            'suspicious_dependencies_count': 0, 'total_dependencies_count': 0,
            
            # Version Analysis (7)
            'is_first_version': 1, 'has_other_versions_today': 0, 'is_rapid_update': 0,
            'version_velocity': 0, 'maintenance_score': 0, 'time_between_updates': 0,
            'update_type': 0,
            
            # Security Patterns (12)
            'fs_read_count': 0, 'fs_write_count': 0, 'fs_delete_count': 0,
            'http_request_count': 0, 'fetch_count': 0, 'socket_count': 0,
            'exec_count': 0, 'spawn_count': 0, 'fork_count': 0,
            'password_access': 0, 'cookie_access': 0, 'env_variable_access': 0,
            
            # Obfuscation & Entropy (6)
            'max_entropy': 0, 'avg_entropy': 0, 'entropy_variance': 0,
            'minified_files': 0, 'minified_ratio': 0, 'obfuscation_score': 0,
            
            # Malicious Patterns (4)
            'base64_pattern_count': 0, 'eval_usage_count': 0,
            'base64_density': 0, 'eval_density': 0,
            
            # Install Script Analysis (7)
            'has_install_command': 0, 'base64_in_install_script': 0,
            'domain_in_install_script': 0, 'network_in_install_script': 0,
            'process_env_in_install_script': 0, 'file_ops_in_install_script': 0,
            'shell_exec_in_install_script': 0,
            
            # Metadata & Hygiene (1)
            'has_readme': 0
        }

    def extract_all_features(self, package_path, package_type="unknown"):
        """Extract all 52 features"""
        basic_features = self.extract_basic_features(package_path)
        advanced_features = self.extract_advanced_features(package_path)
        install_script_features = self.extract_install_script_features(package_path)
        
        # Combine all features
        all_features = {**basic_features, **advanced_features, **install_script_features}
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
