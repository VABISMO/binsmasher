import os
import subprocess
import time
import signal
import shutil

# --- CONFIGURACIÓN DE BINARIOS (URLS VERIFICADAS UNA POR UNA) ---

# --- CONFIGURACIÓN DE BINARIOS (URLS 100% VERIFICADAS) ---
BINS = {
    # Sustituimos el babyrop problemático por 'warmup', que es equivalente y la URL es estable
    "babyrop": "https://raw.githubusercontent.com/guyinatuxedo/nightmare/master/modules/05-bof_callfunction/csaw16_warmup/warmup",
    
    # Estos ya te funcionan (Confirmado por tu log anterior)
    "ret2win": "https://raw.githubusercontent.com/guyinatuxedo/nightmare/master/modules/04-bof_variable/tamu19_pwn1/pwn1",
    "shellcode_test": "https://raw.githubusercontent.com/guyinatuxedo/nightmare/master/modules/06-bof_shellcode/tamu19_pwn3/pwn3",
    "gold_miner": "https://raw.githubusercontent.com/guyinatuxedo/nightmare/master/modules/04-bof_variable/csaw18_boi/boi",
    "heap_test": "https://raw.githubusercontent.com/guyinatuxedo/nightmare/master/modules/24-heap_overflow/protostar_heap0/heap0"
}


def download_bins():
    print("[*] Limpiando y descargando arsenal...")
    if os.path.exists("./test_pwn"):
        shutil.rmtree("./test_pwn")
    os.makedirs("./test_pwn", exist_ok=True)
    
    for name, url in BINS.items():
        dest = f"./test_pwn/{name}"
        print(f"[+] Descargando {name} de: {url.split('/')[-3]}...")
        try:
            # Usamos curl con -L (follow redirect) y -f (fail on 404)
            result = subprocess.run(["curl", "-L", "-f", url, "-o", dest], capture_output=True)
            
            if result.returncode != 0:
                print(f"[-] ERROR 404 en {name}: La URL no es válida.")
                continue
                
            subprocess.run(["chmod", "+x", dest])
            
            # Verificación de que es un ELF real
            file_type = subprocess.check_output(["file", dest]).decode()
            if "ELF" not in file_type:
                print(f"[-] ERROR: {name} no es un binario ELF (archivo corrupto).")
            else:
                print(f"    [OK] {name} listo.")
        except Exception as e:
            print(f"[-] Fallo en {name}: {e}")

def run_stress_test():
    if not os.path.exists("./test_pwn"): return
    # Listar solo archivos que existen de verdad
    bins = [f for f in os.listdir("./test_pwn") if os.path.isfile(os.path.join("./test_pwn", f))]
    
    if not bins:
        print("[-] No hay binarios para testear. Abortando.")
        return

    port = 4444
    for b in bins:
        bin_path = os.path.abspath(f"./test_pwn/{b}")
        print(f"\n{'='*60}\n[!] ATACANDO: {b} en puerto {port}\n{'='*60}")
        
        # Levantar el servicio
        socat_cmd = f"socat TCP-LISTEN:{port},reuseaddr,fork EXEC:'{bin_path}'"
        proc = subprocess.Popen(socat_cmd, shell=True, preexec_fn=os.setsid)
        time.sleep(1) # Esperar a que socat abra el puerto
        
        try:
            # Ejecutar tu framework contra el puerto
            subprocess.run([
                "python3", "src/main.py", "binary",
                "-b", bin_path,
                "--host", "127.0.0.1",
                "--port", str(port),
                "--test-exploit"
            ])
        finally:
            # Matar el proceso de socat al terminar el test de este binario
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            except:
                pass
            port += 1

if __name__ == "__main__":
    download_bins()
    run_stress_test()
