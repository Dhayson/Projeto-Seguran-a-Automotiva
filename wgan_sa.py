import sys
import numpy as np
import pandas as pd
from numpy.random import RandomState
import torch
import torch_optimizer
from ipaddress import IPv4Address
import random
from optuna.pruners import MedianPruner

from WGAN_intrusion_detection.src.transform import MeanNormalizeTensor, MinMaxNormalizeTensor
from WGAN_intrusion_detection.src.into_dataloader import IntoDataset
from WGAN_intrusion_detection.src.wgan.self_attention_wgan import TrainSelfAttention
from WGAN_intrusion_detection.src.early_stop import EarlyStopping
from WGAN_intrusion_detection.src.wgan.wgan import discriminate, Discriminator, Generator, cuda
import WGAN_intrusion_detection.src.metrics as metrics

def main():
    # Hiperparametros
    RANDOM_SEED = 5
    rs = RandomState(RANDOM_SEED)
    DATASET_FORMAT = "csv"
    time_window = 10
    
    args= sys.argv
    
    df_benign = pd.read_csv(args[1])
    df_spoof = pd.read_csv(args[2])
    
    # Essa coluna é importante para a dependência temporal!
    df_train = df_benign.sort_values(by = "timestamp", ignore_index=True)
    df_val = df_spoof
    
    # Rótulo provisório
    # TODO: aplicar rótulo no dataset, combinando logs
    df_val["Label"] = df_val["data_0"] != 0
    df_val_label = df_val["Label"]
    
    # Coluna não usada para treinamento
    df_train = df_train.drop(["timestamp", "Unnamed: 0"], axis=1)
    df_val = df_val.drop(["timestamp", "Unnamed: 0", "Label"], axis=1)
    
    # Dispositivo de trainamento
    cuda = True if torch.cuda.is_available() else False
    device = "cuda" if cuda else "cpu"
    
    # Normalização dos dados
    normalization = MinMaxNormalizeTensor(df_train.max().to_numpy(dtype=np.float32), df_train.min().to_numpy(dtype=np.float32))
     
    # Validação: diferenciar entre benignos (0) e ataques (1)
    # Converte os rótulos para 0 (BENIGN) e 1 (ataque)
    y_val = df_val_label.apply(lambda c: 0 if not c else 1)
    
    dataset_train = IntoDataset(df_train, time_window, normalization)
    dataset_val = IntoDataset(df_val, time_window, normalization)
    if args[3] == "train":
        generator_sa, discriminator_sa = TrainSelfAttention(dataset_train, lrd=0.0007074207502579864, lrg=0.0003427041916020818, epochs=50, 
                    dataset_val=dataset_val, y_val=y_val, wdd=0.0017472655758194694, wdg=0.008333067108096701, clip_value = 0.5036187305772312, optim=torch.optim.Adam,
                    early_stopping=EarlyStopping(15, 0), dropout=0.19560173729322383, latent_dim=15, batch_size=10, n_critic=4,
                    time_window=time_window, headsd=24, embedd=48, headsg=24, embedg=48, data_len=8)
        torch.save(generator_sa, "GeneratorSA.torch")
        torch.save(discriminator_sa, "DiscriminatorSA.torch")
        return
    
    elif args[3] == "val":
        discriminator: Discriminator = torch.load("DiscriminatorSA.torch", weights_only = False, map_location=torch.device(device)).to(device)
        generator: Generator = torch.load("GeneratorSA.torch", weights_only = False, map_location=torch.device(device)).to(device)
        discriminator = discriminator.eval()
        generator = generator.eval()
        preds = discriminate(discriminator, dataset_val, time_window)
        best_thresh = metrics.best_validation_threshold(y_val, preds)
        thresh = best_thresh["thresholds"]
        print(f"VAL AUC: ", metrics.roc_auc_score(y_val, preds))
        print(f"VAL accuracy: ", metrics.accuracy(y_val, preds > thresh))
        print(f"VAL precision: ", metrics.precision_score(y_val, preds > thresh))
        print(f"VAL recall: ", metrics.recall_score(y_val, preds > thresh))
        print(f"VAL f1: ", metrics.f1_score(y_val, preds > thresh))
        print("Tpr: ", best_thresh['tpr'])
        print("Fpr: ", best_thresh['fpr'])
        metrics.plot_confusion_matrix(y_val, preds > thresh, name="Self attention wgan")
        metrics.plot_roc_curve(y_val, preds, name="Self attention wgan")
        
     

if __name__ == '__main__':
    main()