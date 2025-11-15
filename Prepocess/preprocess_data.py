import os
import pandas as pd
import numpy as np
from sklearn.model_selection import StratifiedKFold
from sklearn.preprocessing import StandardScaler
import json

def preprocess_and_split_data():
    """
    Chuẩn hóa dữ liệu và chia thành 4-fold cross-validation
    Dựa trên cấu trúc file features.csv từ AdvancedFeatureExtractor
    """
    
    # Đường dẫn
    current_dir = os.path.dirname(os.path.abspath(__file__))
    features_path = os.path.join(current_dir, "..", "Features", "features.csv")
    output_dir = os.path.join(current_dir, "..", "Formated_Data")
    
    # Tạo thư mục output nếu chưa tồn tại
    os.makedirs(output_dir, exist_ok=True)
    
    # Đọc dữ liệu
    print("Đang đọc dữ liệu từ features.csv...")
    df = pd.read_csv(features_path)
    
    # Kiểm tra dữ liệu
    print(f"Tổng số samples: {len(df)}")
    print(f"Shape của dataset: {df.shape}")
    print(f"Các cột: {df.columns.tolist()}")
    
    # PHÂN TÍCH CẤU TRÚC DỮ LIỆU
    print("\n=== PHÂN TÍCH CẤU TRÚC DỮ LIỆU ===")
    
    # Tìm cột nhãn (package_type) - theo code extract features
    label_column = "package_type"
    if label_column not in df.columns:
        # Fallback: tìm cột có chứa 'benign' và 'malicious'
        for col in df.columns:
            unique_vals = df[col].unique()
            if any('benign' in str(val).lower() or 'malicious' in str(val).lower() for val in unique_vals):
                label_column = col
                print(f"Tìm thấy cột nhãn: {col}")
                break
        else:
            # Nếu không tìm thấy, dùng cột cuối
            label_column = df.columns[-1]
            print(f"Không tìm thấy cột nhãn rõ ràng, sử dụng cột cuối: {label_column}")
    
    # TÁCH FEATURES VÀ LABELS
    # Loại bỏ các cột không phải feature (metadata)
    non_feature_columns = [label_column, 'collection_date', 'analysis_timestamp', 'package_type']
    feature_columns = [col for col in df.columns if col not in non_feature_columns]
    
    X = df[feature_columns]
    y = df[label_column]
    
    print(f"\nSố features: {X.shape[1]}")
    print(f"Cột nhãn: {label_column}")
    print(f"Phân bố nhãn:\n{y.value_counts()}")
    
    # CHUẨN HÓA NHÃN VỀ DẠNG SỐ
    print("\nĐang chuẩn hóa nhãn...")
    label_mapping = {
        'benign': 0,
        'malicious': 1
    }
    
    # Xử lý các giá trị nhãn khác nhau có thể có
    unique_labels = y.unique()
    print(f"Unique labels found: {unique_labels}")
    
    y_encoded = y.map(lambda x: 1 if 'malicious' in str(x).lower() else 0)
    
    print(f"Phân bố nhãn sau encoding:")
    print(f"  Benign (0): {(y_encoded == 0).sum()}")
    print(f"  Malicious (1): {(y_encoded == 1).sum()}")
    
    # KIỂM TRA VÀ LÀM SẠCH DỮ LIỆU FEATURES
    print("\nĐang kiểm tra và làm sạch dữ liệu features...")
    
    # Chuyển đổi tất cả features sang số
    for col in X.columns:
        if X[col].dtype == 'object':
            print(f"Chuyển đổi cột '{col}' từ {X[col].dtype} sang số...")
            try:
                X[col] = pd.to_numeric(X[col], errors='coerce')
            except:
                # Nếu không chuyển được, dùng label encoding
                from sklearn.preprocessing import LabelEncoder
                le = LabelEncoder()
                X[col] = le.fit_transform(X[col].astype(str))
    
    # Xử lý missing values
    missing_before = X.isnull().sum().sum()
    if missing_before > 0:
        print(f"Phát hiện {missing_before} giá trị missing, đang xử lý...")
        X = X.fillna(X.mean())  # Fill với giá trị trung bình
        print(f"Số missing values sau xử lý: {X.isnull().sum().sum()}")
    
    # Loại bỏ các cột có variance bằng 0 (không có thông tin)
    from sklearn.feature_selection import VarianceThreshold
    selector = VarianceThreshold()
    X_clean = selector.fit_transform(X)
    removed_columns = X.columns[~selector.get_support()].tolist()
    
    if removed_columns:
        print(f"Đã loại bỏ {len(removed_columns)} cột có variance bằng 0: {removed_columns}")
        # Cập nhật feature names
        feature_columns = [col for col in feature_columns if col not in removed_columns]
        X = pd.DataFrame(X_clean, columns=feature_columns, index=X.index)
    
    # Chuyển đổi sang numpy array
    X_array = X.values.astype(np.float64)
    y_array = y_encoded.values
    
    print(f"\nShape X sau xử lý: {X_array.shape}")
    print(f"Shape y sau xử lý: {y_array.shape}")
    
    # CHUẨN HÓA DỮ LIỆU
    print("\nĐang chuẩn hóa dữ liệu...")
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_array)
    
    # CHIA DỮ LIỆU THÀNH 4 FOLDS
    print("Đang chia dữ liệu thành 4 folds với StratifiedKFold...")
    skf = StratifiedKFold(n_splits=4, shuffle=True, random_state=42)
    
    # LƯU THÔNG TIN MANIFEST
    manifest = {
        "total_samples": len(df),
        "total_features": X_array.shape[1],
        "label_column": label_column,
        "label_distribution_original": y.value_counts().to_dict(),
        "label_distribution_encoded": {
            "benign (0)": int((y_encoded == 0).sum()),
            "malicious (1)": int((y_encoded == 1).sum())
        },
        "feature_names": feature_columns,
        "feature_info": {
            "total_features_original": len(df.columns) - len(non_feature_columns),
            "features_after_cleaning": X_array.shape[1],
            "removed_zero_variance_features": removed_columns
        },
        "scaler_params": {
            "mean": scaler.mean_.tolist(),
            "scale": scaler.scale_.tolist()
        },
        "preprocessing_info": {
            "missing_values_filled": int(missing_before),
            "stratified_kfold_splits": 4,
            "random_state": 42
        }
    }
    
    # TẠO DICTIONARY ĐỂ LƯU CÁC FOLDS
    folds_data = {}
    
    for fold_idx, (train_idx, test_idx) in enumerate(skf.split(X_scaled, y_array)):
        fold_name = f"fold_{fold_idx + 1}"
        
        # Chia dữ liệu
        X_train, X_test = X_scaled[train_idx], X_scaled[test_idx]
        y_train, y_test = y_array[train_idx], y_array[test_idx]
        
        # Thống kê phân bố nhãn trong fold
        train_benign = (y_train == 0).sum()
        train_malicious = (y_train == 1).sum()
        test_benign = (y_test == 0).sum()
        test_malicious = (y_test == 1).sum()
        
        # Lưu thông tin fold
        folds_data[fold_name] = {
            "train_indices": train_idx.tolist(),
            "test_indices": test_idx.tolist(),
            "train_samples": len(train_idx),
            "test_samples": len(test_idx),
            "train_label_distribution": {
                "benign": int(train_benign),
                "malicious": int(train_malicious)
            },
            "test_label_distribution": {
                "benign": int(test_benign),
                "malicious": int(test_malicious)
            },
            "train_benign_ratio": float(train_benign / len(train_idx)),
            "test_benign_ratio": float(test_benign / len(test_idx))
        }
        
        # Lưu dữ liệu fold thành file numpy
        np.save(os.path.join(output_dir, f"X_train_{fold_name}.npy"), X_train)
        np.save(os.path.join(output_dir, f"X_test_{fold_name}.npy"), X_test)
        np.save(os.path.join(output_dir, f"y_train_{fold_name}.npy"), y_train)
        np.save(os.path.join(output_dir, f"y_test_{fold_name}.npy"), y_test)
        
        print(f"Đã lưu {fold_name}: Train={len(train_idx)} (B:{train_benign}, M:{train_malicious}), Test={len(test_idx)} (B:{test_benign}, M:{test_malicious})")
    
    # LƯU DỮ LIỆU TỔNG
    np.save(os.path.join(output_dir, "X_scaled.npy"), X_scaled)
    np.save(os.path.join(output_dir, "y_labels.npy"), y_array)
    np.save(os.path.join(output_dir, "X_original.npy"), X_array)
    
    # Lưu scaler
    np.save(os.path.join(output_dir, "scaler_mean.npy"), scaler.mean_)
    np.save(os.path.join(output_dir, "scaler_scale.npy"), scaler.scale_)
    
    # Lưu feature names
    with open(os.path.join(output_dir, "feature_names.json"), "w") as f:
        json.dump(feature_columns, f, indent=2)
    
    # Lưu manifest
    with open(os.path.join(output_dir, "data_manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2)
    
    # Lưu folds information
    with open(os.path.join(output_dir, "folds_info.json"), "w") as f:
        json.dump(folds_data, f, indent=2)
    
    # Tạo script để load dữ liệu
    create_loading_script(output_dir)
    
    print("\n" + "="*60)
    print("TIỀN XỬ LÝ HOÀN TẤT")
    print("="*60)
    print(f"Dữ liệu đã được lưu tại: {output_dir}")
    print(f"Tổng số samples: {len(df)}")
    print(f"Số features cuối cùng: {X_array.shape[1]}")
    print(f"Phân bố nhãn:")
    print(f"  Benign: {(y_encoded == 0).sum()} samples")
    print(f"  Malicious: {(y_encoded == 1).sum()} samples")
    print(f"Đã tạo 4 folds với StratifiedKFold (đảm bảo phân bố nhãn đồng đều)")

def create_loading_script(output_dir):
    """Tạo script để load dữ liệu đã xử lý"""
    
    script_content = '''import numpy as np
import json
import os

def load_preprocessed_data(fold_number=None):
    """
    Load dữ liệu đã được tiền xử lý
    
    Args:
        fold_number: Số fold cần load (1-4). Nếu None thì load toàn bộ dữ liệu
    
    Returns:
        Dictionary chứa dữ liệu và thông tin
    """
    
    current_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Load manifest
    with open(os.path.join(current_dir, "data_manifest.json"), "r") as f:
        manifest = json.load(f)
    
    # Load feature names
    with open(os.path.join(current_dir, "feature_names.json"), "r") as f:
        feature_names = json.load(f)
    
    if fold_number is None:
        # Load toàn bộ dữ liệu
        X = np.load(os.path.join(current_dir, "X_scaled.npy"))
        y = np.load(os.path.join(current_dir, "y_labels.npy"))
        
        return {
            "X": X,
            "y": y,
            "feature_names": feature_names,
            "manifest": manifest
        }
    else:
        # Load dữ liệu theo fold
        fold_name = f"fold_{fold_number}"
        
        X_train = np.load(os.path.join(current_dir, f"X_train_{fold_name}.npy"))
        X_test = np.load(os.path.join(current_dir, f"X_test_{fold_name}.npy"))
        y_train = np.load(os.path.join(current_dir, f"y_train_{fold_name}.npy"))
        y_test = np.load(os.path.join(current_dir, f"y_test_{fold_name}.npy"))
        
        # Load folds info
        with open(os.path.join(current_dir, "folds_info.json"), "r") as f:
            folds_info = json.load(f)
        
        return {
            "X_train": X_train,
            "X_test": X_test,
            "y_train": y_train,
            "y_test": y_test,
            "feature_names": feature_names,
            "fold_info": folds_info[fold_name],
            "manifest": manifest
        }

def get_scaler():
    """Load scaler đã được fit"""
    current_dir = os.path.dirname(os.path.abspath(__file__))
    mean = np.load(os.path.join(current_dir, "scaler_mean.npy"))
    scale = np.load(os.path.join(current_dir, "scaler_scale.npy"))
    return mean, scale

def get_feature_names():
    """Load feature names"""
    current_dir = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(current_dir, "feature_names.json"), "r") as f:
        return json.load(f)

# Ví dụ sử dụng:
if __name__ == "__main__":
    # Load toàn bộ dữ liệu
    data = load_preprocessed_data()
    print(f"Toàn bộ dữ liệu: {data['X'].shape}")
    print(f"Feature names: {len(data['feature_names'])} features")
    
    # Load fold 1
    fold_data = load_preprocessed_data(1)
    print(f"Fold 1 - Train: {fold_data['X_train'].shape}, Test: {fold_data['X_test'].shape}")
    print(f"Fold 1 distribution - Train: {fold_data['fold_info']['train_label_distribution']}")
'''
    
    with open(os.path.join(output_dir, "load_data.py"), "w") as f:
        f.write(script_content)

if __name__ == "__main__":
    preprocess_and_split_data()
