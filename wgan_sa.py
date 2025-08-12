import deploy
import sys
import numpy as np
import pandas as pd
from numpy.random import RandomState
import torch
from WGAN_intrusion_detection.src.transform import MeanNormalizeTensor, MinMaxNormalizeTensor
from WGAN_intrusion_detection.src.into_dataloader import IntoDataset
from WGAN_intrusion_detection.src.wgan.self_attention_wgan import TrainSelfAttention
from WGAN_intrusion_detection.src.early_stop import EarlyStopping
from WGAN_intrusion_detection.src.wgan.wgan import discriminate, Discriminator, Generator, cuda
import WGAN_intrusion_detection.src.metrics as metrics

from torch.nn.functional import pad

import logging
import time

logging.basicConfig(filename=f"IDS-{time.time()}.log", level=logging.INFO, format='%(message)s')

def convert_log_line(line: str):
    if line == "Created a socket" or line == "":
        return None
    segments = line.split(" ")
    timestamp = float(segments[0][1:-1])
    body = segments[2]
    body_parts = body.split("#")
    id = int(body_parts[0], 16)
    data = body_parts[1]
    data_bytes = []
    if data == "0" or data == "":
        # Zera os data bytes para mensagens sem dados
        data_bytes = [0]*7
    else:
        for i in range(0, len(data), 2):
            data_bytes.append(int(f"0x{data[i:i+2]}",16))
        
    dir = {
        'authentication_id': id,
        'data_0': data_bytes[0],
        'data_1': data_bytes[1],
        'data_2': data_bytes[2],
        'data_3': data_bytes[3],
        'data_4': data_bytes[4],
        'data_5': data_bytes[5],
        'data_6': data_bytes[6],
    }
    serie = pd.Series(dir)
    return serie

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
    df_val = df_spoof.sort_values(by = "timestamp", ignore_index=True)
    
    # Rótulo provisório
    df_val_label = df_val["Label"]
    
    # Coluna não usada para treinamento
    df_train = df_train.drop(["timestamp", "Unnamed: 0", "Label"], axis=1)
    df_val = df_val.drop(["timestamp", "Unnamed: 0", "Label"], axis=1)
    
    # Dispositivo de trainamento
    cuda = True if torch.cuda.is_available() else False
    device = "cuda" if cuda else "cpu"
    
    # Normalização dos dados
    normalization = MinMaxNormalizeTensor(df_train.max().to_numpy(dtype=np.float32), df_train.min().to_numpy(dtype=np.float32))
     
    # Validação: diferenciar entre benignos (0) e ataques (1)
    # Converte os rótulos para 0 (BENIGN) e 1 (ataque)
    y_val = df_val_label.apply(lambda c: 0 if c == "Benign" else 1)
    
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
        print("Threshold: ", thresh)
        metrics.plot_confusion_matrix(y_val, preds > thresh, name="Self attention wgan")
        metrics.plot_roc_curve(y_val, preds, name="Self attention wgan")
    
    elif args[3] == "deploy":
        # Carrega o discriminador
        discriminator: Discriminator = torch.load("DiscriminatorSA.torch", weights_only = False, map_location=torch.device(device)).to(device)
        discriminator = discriminator.eval()
        frame = pd.DataFrame()
        
        def getFormattedMessageMocked():
            return "(1754943816.0281112) can0 0x43#000000F835000000"
        
        try:
            idx = 0
            while True:
                msg = deploy.getMessageFromBus(deploy.bus)
                conversion = convert_log_line(msg)
                new_row = pd.DataFrame([conversion])
                frame = pd.concat([frame, new_row], ignore_index=True)
                x = frame.iloc[max(0, idx-10):idx+1].to_numpy()
                idx += 1
                x_pad = torch.tensor(x, dtype=torch.float32)
                
                if x.shape[0] != time_window:
                    # Realiza padding nos primeiros pacotes
                    target_size = (time_window, time_window)
                    pad_rows = target_size[0] - x.shape[0]
                    x_pad = pad(x_pad, (0, 0, 0, pad_rows), value=0)
                x_pad = normalization(x_pad)
                x_pad = x_pad.reshape((1,10,8))
                data = x_pad.to(device)
                score = discriminator(data, do_print=False).cpu().detach().numpy()
                
                def createLogLine(score):
                    logging.info(f"({time.time()}) WGAN_SA {"Benign" if score[0][0] else "Attack"}")
                # Threshold pré calculado
                createLogLine(score > 29.552196502685547)

        except KeyboardInterrupt:
            pass
        # Limpeza da interface CAN
        deploy.bus.shutdown()
        
        
     

if __name__ == '__main__':
    main()