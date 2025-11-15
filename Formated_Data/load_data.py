import numpy as np
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
