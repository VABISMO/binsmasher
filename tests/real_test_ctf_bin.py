import os
import subprocess
import time
import signal

# --- CONFIGURACIÓN DE BINARIOS ---
# Usamos una estructura más directa de retos clásicos
BINS = {
    "babyrop": "https://github.com/scv-pwn/Pwn-Challenges/raw/master/babyrop/babyrop",
    "ret2win": "https://github.com/guyinatuxedo/nightmare/raw/master/modules/04-bof_variable/tamu19_pwn1/pwn1",
    "shellcode_test": "https://github.com/guyinatuxedo/nightmare/raw/master/modules/06-bof_shellcode/tamu19_pwn3/pwn3"
}

# --- CONFIGURACIÓN DE SOLANA (Opcional si tienes el validador) ---
SOLANA_RPC = "http://localhost:8899"

def download_bins():
    print("[*] Descargando arsenal de pruebas...")
    os.makedirs("./test_pwn", exist_ok=True)
    for name, url in BINS.items():
        dest = f"./test_pwn/{name}"
        if not os.path.exists(dest):
            print(f"[+] Descargando {name}...")
            # Usamos -L para seguir redirecciones de GitHub
            subprocess.run(["curl", "-L", url, "-o", dest], check=True)
            subprocess.run(["chmod", "+x", dest])

def run_stress_test():
    bins = os.listdir("./test_pwn")
    port = 4444
    
    for b in bins:
        bin_path = os.path.abspath(f"./test_pwn/{b}")
        print(f"\n{'#'*60}\n[!] ATACANDO BINARIO: {b}\n{'#'*60}")
        
        # Levantar el binario con socat
        socat_cmd = f"socat TCP-LISTEN:{port},reuseaddr,fork EXEC:'{bin_path}'"
        proc = subprocess.Popen(socat_cmd, shell=True, preexec_fn=os.setsid)
        time.sleep(1)
        
        try:
            # EJECUCIÓN DE BINSMASHER
            # Aquí es donde BinSmasher debe 'fabricar' el 0-day
            subprocess.run([
                "python3", "src/main.py", "binary",
                "-b", bin_path,
                "--host", "127.0.0.1",
                "--port", str(port),
                "--test-exploit"
            ])
        finally:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            port += 1

def run_solana_audit():
    print(f"\n{'#'*60}\n[!] INICIANDO AUDITORÍA SOLANA SVM\n{'#'*60}")
    # Esto probará tu módulo de Solana contra un RPC (si está activo)
    try:
        subprocess.run([
            "python3", "src/main.py", "solana",
            "--rpc", SOLANA_RPC,
            "--exploit-type", "deser", # Probar vulnerabilidades de deserialización
            "--bpf-fuzz"
        ])
    except Exception as e:
        print(f"[-] No se pudo completar la auditoría Solana: {e}")

if __name__ == "__main__":
    download_bins()
    run_stress_test()
    # run_solana_audit() # Descomenta esto si tienes un validador de test corriendo
