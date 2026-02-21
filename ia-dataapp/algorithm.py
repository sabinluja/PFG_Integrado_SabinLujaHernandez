"""
algorithm.py - Algoritmo enviado por el Consumer al Provider via IDS.
El Provider ejecuta este fichero en sus 3 instancias de ia-dataapp.

REQUISITO: debe tener una función run(data_path) que devuelva un dict.
"""
import pandas as pd


def run(data_path: str) -> dict:
    """
    Función principal que ejecuta el algoritmo sobre el CSV del Provider.
    
    Args:
        data_path: Ruta al CSV en el Provider (/home/nobody/data/test1.csv)
    
    Returns:
        dict con los resultados del análisis
    """
    df = pd.read_csv(data_path)

    result = {
        "rows": len(df),
        "columns": list(df.columns),
        "summary": {}
    }

    # Estadísticas por columna numérica
    numeric_cols = df.select_dtypes(include="number").columns
    for col in numeric_cols:
        result["summary"][col] = {
            "mean": round(df[col].mean(), 4),
            "std": round(df[col].std(), 4),
            "min": round(df[col].min(), 4),
            "max": round(df[col].max(), 4),
            "median": round(df[col].median(), 4)
        }

    return result