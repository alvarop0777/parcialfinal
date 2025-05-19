import os
import re
import requests
import json
from collections import defaultdict

# Usar la carpeta actual donde está el script
carpeta = os.path.dirname(os.path.abspath(__file__))

# Regex para extraer: IP, fecha, método HTTP, ruta
regex_pattern = re.compile(
    r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*?\[([^\]]+)\].*?"([A-Z]+)\s+([^\s"]+)',
    re.IGNORECASE
)

def extraer_datos_log(file_path):
    """Extrae IP, fecha, método HTTP y ruta de un archivo de log"""
    resultados = []
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            contenido = f.read()
        
        matches = regex_pattern.findall(contenido)
        for ip, fecha, metodo, ruta in matches:
            resultados.append((ip, fecha, metodo, ruta))
    
    except Exception as e:
        print(f"Error al procesar {file_path}: {e}")
    
    return resultados

def obtener_pais(ip):
    """Obtiene el país de origen de una IP"""
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        if response.status_code == 200:
            data = response.json()
            return data.get("country", "Desconocido")
        return "Desconocido"
    except:
        return "Desconocido"

def generar_json(datos_log):
    """Genera JSON agrupado por país con total de ataques"""
    paises = defaultdict(list)
    cache_paises = {}
    
    for ip, fecha, metodo, ruta in datos_log:
        # Obtener país (con cache para evitar consultas repetidas)
        if ip not in cache_paises:
            cache_paises[ip] = obtener_pais(ip)
        
        pais = cache_paises[ip]
        paises[pais].append({
            "ip": ip,
            "fecha": fecha,
            "metodo": metodo,
            "ruta": ruta
        })
    
    # Convertir a formato con total de ataques
    resultado = {}
    for pais, ataques in paises.items():
        resultado[pais] = {
            "total_ataques": len(ataques),
            "ataques": ataques
        }
    
    return resultado

def main():
    # Buscar archivos de log
    archivos_log = []
    for archivo in ['access', 'access_log']:
        ruta = os.path.join(carpeta, archivo)
        if os.path.isfile(ruta):
            archivos_log.append(archivo)
    
    if not archivos_log:
        print("No se encontraron archivos de log")
        return
    
    # Procesar archivos
    todos_los_datos = []
    for archivo in archivos_log:
        ruta = os.path.join(carpeta, archivo)
        datos = extraer_datos_log(ruta)
        todos_los_datos.extend(datos)
    
    print(f"Se procesaron {len(todos_los_datos)} entradas")
    
    # Generar JSON
    resultado = generar_json(todos_los_datos)
    
    # Guardar JSON
    with open("resultado_ataques.json", "w", encoding="utf-8") as f:
        json.dump(resultado, f, indent=4, ensure_ascii=False)
    
    print("JSON guardado en 'resultado_ataques.json'")

if __name__ == "__main__":
    main()