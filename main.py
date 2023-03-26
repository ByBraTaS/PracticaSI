import pandas as pd
import sqlite3
import json
import matplotlib.pyplot as plt
import matplotlib.dates as mdates


def createBase(con):
    #alerts to database
    alerts = pd.read_csv("data/alerts.csv")
    alerts.to_sql("alerts", con, if_exists="replace", index=False)

    #devices to database
    dev = open("data/devices.json")
    devices = json.load(dev)

    #tables
    cur = con.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS devices (id TEXT PRIMARY KEY, ip TEXT, localizacion TEXT, responsable_id TEXT, puertos_abiertos TEXT, no_puertos_abiertos INTEGER, servicios INTEGER, servicios_inseguros INTEGER, vulnerabilidades_detectadas INTEGER)")
    cur.execute("CREATE TABLE IF NOT EXISTS responsable (nombre TEXT PRIMARY KEY, telefono TEXT, rol TEXT)")

    for d in devices:
        responsable = d['responsable']
        cur.execute("INSERT OR IGNORE INTO responsable (nombre,telefono,rol) VALUES (?, ?, ?)", (responsable['nombre'], responsable['telefono'], responsable['rol']))
        analisis = d['analisis']
        if analisis["puertos_abiertos"] == 'None':
            ports = 0
        else:
            ports = len(analisis["puertos_abiertos"])
        cur.execute("INSERT OR IGNORE INTO devices (id, ip, localizacion, responsable_id, puertos_abiertos, no_puertos_abiertos, servicios, servicios_inseguros, vulnerabilidades_detectadas) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", (d['id'], d['ip'], d['localizacion'], responsable['nombre'], json.dumps(analisis['puertos_abiertos']), ports, analisis['servicios'], analisis['servicios_inseguros'], analisis['vulnerabilidades_detectadas']))

def ex2(con):
    devices = pd.read_sql_query("SELECT * from devices", con)
    alerts = pd.read_sql_query("SELECT * from alerts", con)
    print("Ejercicio 2:")
    print("Número de dispositivos: ",devices.shape[0])
    print("Número de alertas: ", alerts.shape[0])
    print("Media de puertos abiertos: ", devices['no_puertos_abiertos'].mean())
    print("Desviación estandar de puertos abiertos: ", devices['no_puertos_abiertos'].std())
    print("Media de servicios inseguros: ", devices['servicios_inseguros'].mean())
    print("Desviación estandar de servicios inseguros: ", devices['servicios_inseguros'].std())
    print("Media de vulnerabilidades encontradas: ", devices['vulnerabilidades_detectadas'].mean())
    print("Desviación estandar de vulnerabilidades encontradas: ", devices['vulnerabilidades_detectadas'].std())
    print("Mínimo de puertos abiertos: ", devices['no_puertos_abiertos'].min())
    print("Máximo de puertos abiertos: ", devices['no_puertos_abiertos'].max())
    print("Mínimo de vulnerabilidades encontradas: ", devices['vulnerabilidades_detectadas'].min())
    print("Máximo de vulnerabilidades encontradas: ", devices['vulnerabilidades_detectadas'].max())
    print()


def ex3(con):
    print("Ejercicio 3:")
    print("Por prioridad")
    vulnerabilitiesPrio = pd.read_sql_query("SELECT prioridad, vulnerabilidades_detectadas FROM devices JOIN ( SELECT  prioridad, origen, destino FROM alerts ORDER BY prioridad) ON ip = origen OR ip = destino", con)
    for i in range(1, 4):
        print("Prioridad ",i)
        priority = vulnerabilitiesPrio[(vulnerabilitiesPrio['prioridad'] == i)]
        print("Numero de observaciones: ", priority.shape[0])
        print("Mediana de vulnerabilidades detectadas: ", priority["vulnerabilidades_detectadas"].median())
        print("Media de vulnerabilidades detectadas: ", priority["vulnerabilidades_detectadas"].mean())
        print("Varianza de vulnerabilidades detectadas: ", priority["vulnerabilidades_detectadas"].var())
        print("Valor máximo de vulnerabilidades detectadas: ", priority["vulnerabilidades_detectadas"].max())
        print("Valor mínimo de vulnerabilidades detectadas: ", priority["vulnerabilidades_detectadas"].min())
        print()

    print("Por fecha:")
    vulnerabilitiesDate = pd.read_sql_query("SELECT timestamp, vulnerabilidades_detectadas FROM devices JOIN ( SELECT timestamp, origen, destino FROM alerts ORDER BY timestamp) ON ip = origen OR ip = destino",con)
    vulnerabilitiesDate['timestamp'] = pd.to_datetime(vulnerabilitiesDate['timestamp'])
    for i in range(7,9):
        date = vulnerabilitiesDate[(vulnerabilitiesDate['timestamp'].dt.month == i)]
        if i==7:
            print("Julio:")
        else:
            print("Agosto")
        print("Numero de observaciones: ", date.shape[0])
        print("Mediana de vulnerabilidades detectadas: ", date["vulnerabilidades_detectadas"].median())
        print("Media de vulnerabilidades detectadas: ", date["vulnerabilidades_detectadas"].mean())
        print("Varianza de vulnerabilidades detectadas: ", date["vulnerabilidades_detectadas"].var())
        print("Valor máximo de vulnerabilidades detectadas: ", date["vulnerabilidades_detectadas"].max())
        print("Valor mínimo de vulnerabilidades detectadas: ", date["vulnerabilidades_detectadas"].min())
        print()

def ex4(con):
    cur = con.cursor()
    cur.execute("SELECT origen, COUNT(*) as num_alertas FROM alerts WHERE prioridad = 1 GROUP BY origen ORDER BY num_alertas DESC LIMIT 10")
    ips = []
    num = []
    for row in cur.fetchall():
        ips.append(row[0])
        num.append(row[1])
    plt.bar(ips, num)
    plt.xticks(rotation=25)
    plt.title('IP de origen más problemáticas')
    plt.xlabel('IP de origen')
    plt.ylabel('Número de alertas')
    plt.show()

    cur.execute("SELECT strftime('%Y-%m-%d',timestamp), COUNT(*) FROM alerts GROUP BY strftime('%Y-%m-%d',timestamp)")
    fechas = []
    num2 = []
    for row in cur.fetchall():
        fechas.append(row[0])
        num2.append(row[1])
    fig, ax = plt.subplots()
    ax.plot(fechas, num2)
    plt.xticks(rotation=25)
    ax.set_title('Número de alertas por día')
    ax.set_xlabel('Fecha')
    ax.set_ylabel('Número de alertas')
    ax.xaxis.set_major_locator(mdates.DayLocator(interval=7))
    plt.show()

    cur.execute("SELECT clasificacion, COUNT(*) as num_alertas FROM alerts GROUP BY clasificacion")
    cat = []
    num3 = []
    for row in cur.fetchall():
        cat.append(row[0])
        num3.append(row[1])
    plt.bar(cat, num3)
    plt.xticks(fontsize=5)
    plt.xticks(rotation=20, ha='right')
    plt.title('Número de alertas por categorías')
    plt.xlabel('Categorías')
    plt.ylabel('Número de alertas')
    plt.show()

    cur.execute("SELECT id,SUM(servicios_inseguros + vulnerabilidades_detectadas) FROM devices GROUP BY id")
    dev = []
    num4 = []
    for row in cur.fetchall():
        dev.append(row[0])
        num4.append(row[1])
    plt.bar(dev, num4)
    plt.xticks(rotation=25)
    plt.title('Dispositivos más vulnerables')
    plt.xlabel('Dispositivo')
    plt.ylabel('Servicios vulnerables + vulnerabilidades')
    plt.show()

    cur.execute("SELECT servicios_inseguros,AVG(no_puertos_abiertos) FROM devices GROUP BY servicios_inseguros")
    ser = []
    num5 = []
    for row in cur.fetchall():
        ser.append(row[0])
        num5.append(row[1])
    plt.bar(ser, num5)
    plt.xticks(rotation=25)
    plt.title('Puertos abiertos por servicios vulnerables')
    plt.xlabel('Servicios vulnerables')
    plt.ylabel('Media de puertos abiertos')
    plt.show()

    cur.execute("SELECT servicios,AVG(no_puertos_abiertos) FROM devices GROUP BY servicios")
    ser2 = []
    num6 = []
    for row in cur.fetchall():
        ser2.append(row[0])
        num6.append(row[1])
    plt.bar(ser2, num6)
    plt.xticks(rotation=25)
    plt.title('Puertos abiertos por servicios totales')
    plt.xlabel('Servicios totales')
    plt.ylabel('Media de puertos abiertos')
    plt.show()


con = sqlite3.connect("database.db")
createBase(con)
ex2(con)
ex3(con)
ex4(con)
con.commit()

