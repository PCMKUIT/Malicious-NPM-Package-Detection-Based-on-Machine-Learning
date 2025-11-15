import os
import numpy as np
from prettytable import PrettyTable
from sklearn.model_selection import StratifiedKFold, cross_validate, cross_val_predict
from sklearn.metrics import confusion_matrix, accuracy_score, f1_score, make_scorer, matthews_corrcoef, precision_score, recall_score
from sklearn.svm import SVC
import pickle
import json
import re

# Configuration
class Config:
    """Configuration class for SVM training"""
    GAMMAS = [0.1, 0.01, 0.001, 0.0001]
    C_VALUES = [0.1, 1, 10, 100]
    K_FOLDS = 4
    RANDOM_STATE = 42

class SVM_Trainer:
    def __init__(self):
        self.current_dir = os.path.dirname(os.path.abspath(__file__))
        self.formated_data_dir = os.path.join(self.current_dir, "..", "Formated_Data")
        
        # Create SVM-specific directories
        self.svm_dir = os.path.join(self.current_dir, "SVM")
        self.results_dir = os.path.join(self.svm_dir, "results")
        self.models_dir = os.path.join(self.svm_dir, "models")
        
        # Create directories if not exist
        os.makedirs(self.results_dir, exist_ok=True)
        os.makedirs(self.models_dir, exist_ok=True)
        
        # Define scoring metrics với đúng tên
        self.scoring = {
            "accuracy": make_scorer(accuracy_score),
            "precision": make_scorer(precision_score, pos_label=1),  # malicious is 1
            "recall": make_scorer(recall_score, pos_label=1),        # malicious is 1
            "f1": make_scorer(f1_score, pos_label=1),               # malicious is 1
            "matthews_corrcoef": make_scorer(matthews_corrcoef)
        }
        
        self.field_names = ["Hyperparameters", "TP", "FP", "TN", "FN", "Accuracy", "Precision", "Recall", "F1", "MCC"]

    def load_preprocessed_data(self, fold_number=None):
        """
        Load preprocessed data from Formated_Data directory
        """
        try:
            # Load manifest for information
            with open(os.path.join(self.formated_data_dir, "data_manifest.json"), "r") as f:
                manifest = json.load(f)
            
            # Load feature names
            with open(os.path.join(self.formated_data_dir, "feature_names.json"), "r") as f:
                feature_names = json.load(f)
            
            if fold_number is None:
                # Load all data
                X = np.load(os.path.join(self.formated_data_dir, "X_scaled.npy"))
                y = np.load(os.path.join(self.formated_data_dir, "y_labels.npy"))
                
                return {
                    "X": X,
                    "y": y,
                    "feature_names": feature_names,
                    "manifest": manifest
                }
            else:
                # Load specific fold
                fold_name = f"fold_{fold_number}"
                
                X_train = np.load(os.path.join(self.formated_data_dir, f"X_train_{fold_name}.npy"))
                X_test = np.load(os.path.join(self.formated_data_dir, f"X_test_{fold_name}.npy"))
                y_train = np.load(os.path.join(self.formated_data_dir, f"y_train_{fold_name}.npy"))
                y_test = np.load(os.path.join(self.formated_data_dir, f"y_test_{fold_name}.npy"))
                
                # Load folds info
                with open(os.path.join(self.formated_data_dir, "folds_info.json"), "r") as f:
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
                
        except Exception as e:
            print(f"Error loading preprocessed data: {e}")
            return None

    def train_svm_validate(self):
        """
        Train SVM model with cross-validation and hyperparameter tuning
        """
        print("=== SVM MODEL TRAINING WITH CROSS-VALIDATION ===")
        
        # Load all data for cross-validation
        data = self.load_preprocessed_data()
        if data is None:
            print("Failed to load preprocessed data!")
            return None
        
        X = data["X"]
        y = data["y"]
        
        print(f"Dataset shape: {X.shape}")
        print(f"Label distribution: {np.unique(y, return_counts=True)}")
        print(f"Number of features: {len(data['feature_names'])}")
        
        # Setup cross-validation
        skf = StratifiedKFold(n_splits=Config.K_FOLDS, shuffle=True, random_state=Config.RANDOM_STATE)
        
        # Create results table
        table = PrettyTable()
        csv_path = os.path.join(self.results_dir, "SVM_validation.csv")
        table.field_names = self.field_names
        
        print(f"\nTesting {len(Config.C_VALUES)} C values and {len(Config.GAMMAS)} gamma values...")
        print(f"Total combinations: {len(Config.C_VALUES) * len(Config.GAMMAS)}")
        
        successful_combinations = 0
        
        with open(csv_path, "w+", encoding='utf-8') as f:
            for C_val in Config.C_VALUES:
                for gamma_val in Config.GAMMAS:
                    print(f"Training SVM with C={C_val}, gamma={gamma_val}...")
                    
                    try:
                        # Create SVM model
                        model = SVC(kernel="rbf", C=C_val, gamma=gamma_val, random_state=Config.RANDOM_STATE)
                        
                        # Perform cross-validation với scoring đúng
                        scores = cross_validate(model, X, y, cv=skf, scoring=self.scoring, return_train_score=False)
                        
                        # Get predictions for confusion matrix
                        y_pred = cross_val_predict(model, X, y, cv=skf)
                        
                        # Calculate confusion matrix
                        tn, fp, fn, tp = confusion_matrix(y, y_pred).ravel()
                        
                        # Add row to table
                        table.add_row([
                            f"C={C_val}; gamma={gamma_val}",
                            tp, fp, tn, fn,
                            f"{scores['test_accuracy'].mean():.4f}",
                            f"{scores['test_precision'].mean():.4f}",
                            f"{scores['test_recall'].mean():.4f}",
                            f"{scores['test_f1'].mean():.4f}",
                            f"{scores['test_matthews_corrcoef'].mean():.4f}"
                        ])
                        
                        successful_combinations += 1
                        print(f"  ✓ Success - Acc: {scores['test_accuracy'].mean():.4f}, F1: {scores['test_f1'].mean():.4f}")
                        
                    except Exception as e:
                        print(f"  ✗ Error: {e}")
                        continue
            
            # Save table to CSV
            f.write(table.get_csv_string())
        
        print(f"\nSuccessful combinations: {successful_combinations}/{len(Config.C_VALUES) * len(Config.GAMMAS)}")
        print(f"Results saved to: {csv_path}")
        
        if successful_combinations > 0:
            print("\nCross-validation results:")
            print(table)
        else:
            print("\nNo successful training combinations!")
        
        return table if successful_combinations > 0 else None

    def find_best_parameters(self, results_table):
        """
        Find the best hyperparameters from validation results
        """
        if results_table is None or len(results_table._rows) == 0:
            print("No results available to find best parameters")
            return None, None
            
        best_f1 = 0
        best_params = None
        
        for row in results_table._rows:
            params_str = row[0]
            f1_score = float(row[8])  # F1 score is at index 8
            
            if f1_score > best_f1:
                best_f1 = f1_score
                best_params = params_str
        
        if best_params:
            print(f"\nBest parameters: {best_params}")
            print(f"Best F1 score: {best_f1:.4f}")
            
            # Extract C and gamma from best_params string
            c_match = re.search(r'C=([\d.]+)', best_params)
            gamma_match = re.search(r'gamma=([\d.]+)', best_params)
            
            if c_match and gamma_match:
                best_C = float(c_match.group(1))
                best_gamma = float(gamma_match.group(1))
                return best_C, best_gamma
        
        return None, None

    def save_svm_model(self, X_train, y_train, gamma, C):
        """
        Save the trained SVM model
        """
        try:
            model = SVC(C=C, gamma=gamma, kernel="rbf", random_state=Config.RANDOM_STATE)
            model.fit(X_train, y_train)
            
            save_path = os.path.join(self.models_dir, "SVM.pkl")
            with open(save_path, "wb") as f:
                pickle.dump(model, f)
            
            print(f"Model saved to: {save_path}")
            return model
            
        except Exception as e:
            print(f"Error saving model: {e}")
            return None

    def train_final_model(self, best_C, best_gamma):
        """
        Train final model with best parameters on entire dataset
        """
        print(f"\n=== TRAINING FINAL MODEL WITH BEST PARAMETERS ===")
        print(f"Best C: {best_C}, Best gamma: {best_gamma}")
        
        # Load all data for final training
        data = self.load_preprocessed_data()
        if data is None:
            print("Failed to load data for final training!")
            return None
        
        X = data["X"]
        y = data["y"]
        
        # Train and save final model
        final_model = self.save_svm_model(X, y, best_gamma, best_C)
        
        if final_model:
            # Evaluate on training data
            train_accuracy = final_model.score(X, y)
            y_pred = final_model.predict(X)
            tn, fp, fn, tp = confusion_matrix(y, y_pred).ravel()
            
            print(f"\nFinal Model Performance on Training Data:")
            print(f"Accuracy: {train_accuracy:.4f}")
            print(f"Confusion Matrix: TP={tp}, FP={fp}, TN={tn}, FN={fn}")
            print(f"Precision: {precision_score(y, y_pred, pos_label=1):.4f}")
            print(f"Recall: {recall_score(y, y_pred, pos_label=1):.4f}")
            print(f"F1 Score: {f1_score(y, y_pred, pos_label=1):.4f}")
            print(f"MCC: {matthews_corrcoef(y, y_pred):.4f}")
            
            # Save performance metrics
            performance = {
                "best_parameters": {
                    "C": best_C,
                    "gamma": best_gamma
                },
                "performance_metrics": {
                    "accuracy": float(train_accuracy),
                    "precision": float(precision_score(y, y_pred, pos_label=1)),
                    "recall": float(recall_score(y, y_pred, pos_label=1)),
                    "f1_score": float(f1_score(y, y_pred, pos_label=1)),
                    "mcc": float(matthews_corrcoef(y, y_pred)),
                    "confusion_matrix": {
                        "true_positive": int(tp),
                        "false_positive": int(fp),
                        "true_negative": int(tn),
                        "false_negative": int(fn)
                    }
                },
                "dataset_info": {
                    "total_samples": len(y),
                    "benign_samples": int((y == 0).sum()),
                    "malicious_samples": int((y == 1).sum()),
                    "feature_count": X.shape[1]
                }
            }
            
            # Save performance to JSON
            perf_path = os.path.join(self.results_dir, "SVM_performance.json")
            with open(perf_path, "w") as f:
                json.dump(performance, f, indent=2)
            print(f"Performance metrics saved to: {perf_path}")
        
        return final_model

    def run(self):
        """
        Main training pipeline
        """
        print("Starting SVM Training Pipeline...")
        print(f"SVM Directory: {self.svm_dir}")
        print(f"Results Directory: {self.results_dir}")
        print(f"Models Directory: {self.models_dir}")
        
        # Step 1: Cross-validation with hyperparameter tuning
        results_table = self.train_svm_validate()
        
        # Step 2: Find best parameters
        if results_table:
            best_C, best_gamma = self.find_best_parameters(results_table)
        else:
            best_C, best_gamma = None, None
        
        if best_C is None or best_gamma is None:
            print("Using default parameters: C=1.0, gamma=0.01")
            best_C, best_gamma = 1.0, 0.01
        
        # Step 3: Train final model with best parameters
        final_model = self.train_final_model(best_C, best_gamma)
        
        print("\n=== SVM TRAINING COMPLETED ===")
        print(f"Model: {os.path.join(self.models_dir, 'SVM.pkl')}")
        print(f"Results: {os.path.join(self.results_dir, 'SVM_validation.csv')}")

def main():
    """Main function"""
    trainer = SVM_Trainer()
    trainer.run()

if __name__ == "__main__":
    main()
