import os
import json
import math
import hashlib
import csv
from pathlib import Path
from collections import Counter
from datetime import datetime
from packaging.version import Version, InvalidVersion
#Cần tải tree sitter và laguage binding : pip install tree-sitter & pip install tree-sitter-javascript

try:
    from tree_sitter import Language, Parser
    import tree_sitter_javascript as tsjs
    TREE_SITTER_AVAILABLE = True
    JS_LANGUAGE = Language(tsjs.language())
except ImportError:
    TREE_SITTER_AVAILABLE = False
    print("Warning: Tree-sitter not available. Some advanced features will be disabled.")

class AdvancedFeatureExtractor:
    """Combined feature extractor for both basic and advanced analysis"""
    
    def __init__(self):
        self.pii_keywords = ["password", "creditcard", "cookie", "secret", "token", "api_key"]
    
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

    def extract_sensitive_code_features(self, js_code):
        """Extract features using Tree-sitter for sensitive JavaScript patterns."""
        if not TREE_SITTER_AVAILABLE or not js_code:
            return {
                "system_command_usage": 0,
                "file_access": 0,
                "env_variable_access": 0,
                "network_access": 0,
                "crypto_usage": 0,
                "data_encoding": 0,
                "dynamic_code_generation": 0,
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
            }

            def traverse(node):
                if node.type == "call_expression":
                    func_node = node.child_by_field_name("function")
                    if func_node:
                        func_name = func_node.text.decode("utf8")
                        if "fs." in func_name and any(op in func_name for op in ["read", "write", "unlink"]):
                            features["file_access"] += 1
                        elif "process.env" in func_name:
                            features["env_variable_access"] += 1
                        elif any(cmd in func_name for cmd in ["exec", "spawn"]):
                            features["system_command_usage"] += 1
                        elif any(net in func_name for net in ["http.", "https.", "fetch"]):
                            features["network_access"] += 1
                        elif "crypto." in func_name:
                            features["crypto_usage"] += 1
                        elif any(dyn in func_name for dyn in ["eval", "Function", "setTimeout", "setInterval"]):
                            features["dynamic_code_generation"] += 1
                        elif any(enc in func_name for enc in ["encodeURIComponent", "decodeURIComponent", "btoa", "atob"]):
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
            }

    def extract_dependencies_count(self, package_data):
        """Extract total dependencies count from package.json"""
        DEPENDENCY_FIELDS = [
            "dependencies",
            "devDependencies", 
            "peerDependencies",
            "optionalDependencies",
            "bundleDependencies",
            "bundledDependencies",
        ]

        dependencies_count = 0
        for field in DEPENDENCY_FIELDS:
            if field in package_data:
                dependencies = package_data.get(field, {})
                dependencies_count += len(dependencies)

        return dependencies_count

    def extract_advanced_features(self, package_dir):
        """Extract advanced features using Tree-sitter and entropy analysis"""
        features = {
            # Entropy features
            "max_entropy": 0,
            "avg_entropy": 0,
            "minified_files": 0,
            "binary_files": 0,
            "pii_keywords_count": 0,
            
            # Security features
            "system_command_usage": 0,
            "file_access": 0, 
            "env_variable_access": 0,
            "network_access": 0,
            "crypto_usage": 0,
            "data_encoding": 0,
            "dynamic_code_generation": 0,
        }

        file_sizes = []
        entropies = []
        total_files = 0

        for root, _, files in os.walk(package_dir):
            for file in files:
                filepath = os.path.join(root, file)
                total_files += 1
                
                try:
                    file_size = os.path.getsize(filepath)
                    file_sizes.append(file_size)

                    if self.detect_binary(filepath):
                        features["binary_files"] += 1
                        continue

                    content = self.read_file(filepath)
                    if content:
                        entropy = self.calculate_entropy(content)
                        entropies.append(entropy)

                        # Detect PII keywords
                        features["pii_keywords_count"] += sum(
                            keyword in content.lower() for keyword in self.pii_keywords
                        )

                        # Minified file detection
                        if len(content.splitlines()) < 5 and len(content) > 500:
                            features["minified_files"] += 1

                        # JavaScript code analysis
                        if file.endswith(".js"):
                            js_features = self.extract_sensitive_code_features(content)
                            for key, value in js_features.items():
                                features[key] += value

                except Exception:
                    continue

        # Calculate entropy statistics
        if entropies:
            features["max_entropy"] = max(entropies)
            features["avg_entropy"] = sum(entropies) / len(entropies)

        return features

    def extract_basic_features(self, package_path):
        """Extract basic structural features (from your original code)"""
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
            if package_json_path and package_json_path.exists():
                try:
                    with open(package_json_path, 'r', encoding='utf-8', errors='ignore') as f:
                        package_data = json.load(f)
                    
                    features['dependencies_count'] = len(package_data.get('dependencies', {}))
                    features['dev_dependencies_count'] = len(package_data.get('devDependencies', {}))
                    features['scripts_count'] = len(package_data.get('scripts', {}))
                    features['has_preinstall'] = 1 if 'preinstall' in package_data.get('scripts', {}) else 0
                    features['has_postinstall'] = 1 if 'postinstall' in package_data.get('scripts', {}) else 0
                    features['has_preuninstall'] = 1 if 'preuninstall' in package_data.get('scripts', {}) else 0
                    
                    features['package_version'] = package_data.get('version', '1.0.0')
                    features['package_name'] = package_data.get('name', 'unknown')
                except (json.JSONDecodeError, UnicodeDecodeError):
                    features['dependencies_count'] = 0
                    features['dev_dependencies_count'] = 0
                    features['scripts_count'] = 0
                    features['has_preinstall'] = 0
                    features['has_postinstall'] = 0
                    features['has_preuninstall'] = 0
                    features['package_version'] = '1.0.0'
                    features['package_name'] = 'unknown'
            else:
                features['dependencies_count'] = 0
                features['dev_dependencies_count'] = 0
                features['scripts_count'] = 0
                features['has_preinstall'] = 0
                features['has_postinstall'] = 0
                features['has_preuninstall'] = 0
                features['package_version'] = '1.0.0'
                features['package_name'] = 'unknown'
            
            # 4. Content Features
            features['has_readme'] = 1 if any('readme' in str(file).lower() for file in files) else 0
            features['has_license'] = 1 if any('license' in str(file).lower() for file in files) else 0
            
        except Exception as e:
            print(f"Error extracting basic features: {e}")
            # Set default values
            features = {
                'file_count': 0, 'total_size_kb': 0, 'has_node_modules': 0,
                'js_file_ratio': 0, 'json_file_ratio': 0, 'dependencies_count': 0,
                'dev_dependencies_count': 0, 'scripts_count': 0, 'has_preinstall': 0,
                'has_postinstall': 0, 'has_preuninstall': 0, 'has_readme': 0,
                'has_license': 0, 'package_version': '1.0.0', 'package_name': 'unknown'
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

def process_dataset_directory(dataset_dir, output_dir, package_type="unknown"):
    """
    Process entire dataset directory structure and extract features
    """
    dataset_dir = Path(dataset_dir)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    extractor = AdvancedFeatureExtractor()
    
    # Create combined CSV for all packages
    combined_csv_path = output_dir / "all_packages_features.csv"
    combined_writer = None
    combined_file = None
    
    # Process each date directory
    for date_dir in dataset_dir.iterdir():
        if date_dir.is_dir():
            print(f"Processing date directory: {date_dir.name}")
            
            # Process each package in date directory
            for package_dir in date_dir.iterdir():
                if package_dir.is_dir():
                    try:
                        print(f"  Extracting features from: {package_dir.name}")
                        
                        # Extract all features
                        features = extractor.extract_all_features(package_dir, package_type)
                        
                        # Write to combined CSV
                        if combined_writer is None:
                            combined_file = open(combined_csv_path, 'w', newline='', encoding='utf-8')
                            combined_writer = csv.DictWriter(combined_file, fieldnames=features.keys())
                            combined_writer.writeheader()
                        
                        combined_writer.writerow(features)
                        
                        # Create individual CSV for this package (organize.py functionality)
                        package_output_dir = output_dir / package_type / date_dir.name / package_dir.name
                        package_output_dir.mkdir(parents=True, exist_ok=True)
                        
                        individual_csv_path = package_output_dir / "change-features.csv"
                        with open(individual_csv_path, 'w', newline='', encoding='utf-8') as f:
                            writer = csv.writer(f)
                            writer.writerow(["feature", "value"])
                            for feature, value in features.items():
                                writer.writerow([feature, value])
                        
                        print(f"    Saved: {individual_csv_path}")
                        
                    except Exception as e:
                        print(f"    Error processing {package_dir.name}: {e}")
    
    if combined_file:
        combined_file.close()
        print(f"Combined features saved to: {combined_csv_path}")

def main():
    """Main function to process both Benign and Malicious datasets"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Extract features from NPM packages dataset")
    parser.add_argument("--dataset-dir", default="Dataset", help="Root dataset directory")
    parser.add_argument("--output-dir", default="Features", help="Output directory for features")
    
    args = parser.parse_args()
    
    dataset_dir = Path(args.dataset_dir)
    output_dir = Path(args.output_dir)
    
    # Process BenignDataset
    benign_dir = dataset_dir / "BenignDataset"
    if benign_dir.exists():
        print("Processing BenignDataset...")
        process_dataset_directory(benign_dir, output_dir / "benign", "benign")
    else:
        print(f"BenignDataset directory not found: {benign_dir}")
    
    # Process MaliciousDataset  
    malicious_dir = dataset_dir / "MaliciousDataset"
    if malicious_dir.exists():
        print("Processing MaliciousDataset...")
        process_dataset_directory(malicious_dir, output_dir / "malicious", "malicious")
    else:
        print(f"MaliciousDataset directory not found: {malicious_dir}")
    
    print("Feature extraction completed!")

if __name__ == "__main__":
    main()
