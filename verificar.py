#!/usr/bin/env python3
"""Testigo de forja de Servidor (servidor ADR-222, residuo R1 de ADR-221).

Corre en GitHub Actions, en un repo PROPIO del operador al que ninguna credencial de O puede escribir. Lee `alexisoller-cpu/servidor` con un
token de SÓLO LECTURA guardado en los secretos de GitHub (root de O no lo ve), y guarda lo que ha visto en ESTE repo (root de O no puede
reescribirlo). Si algo falla, el job falla y GitHub avisa por correo al operador: fuera de O, sin depender de O.

Detecta, en CADA commit que tocó la tabla desde la última corrida buena (no sólo en el estado final: un cambio deshecho antes del cron también sale):
  1. reescritura de historia: el master anterior ya no es antepasado del actual (force-push);
  2. capability borrada: un id que alguna vez estuvo en la tabla falta (se retiran con RETIRADA/FUSIONADA, nunca se borran);
  3. fila protegida (procedencia OPERADOR o dominio legal, antes O después del cambio) que cambia de sentido, se retira, ENTRA en protección o
     NACE protegida sin aprobación del operador en `aprobaciones.tsv` de ESTE repo: una línea `<id> <huella>` por cambio, con la huella
     (128 bits) del sentido nuevo; aprobar un cambio no aprueba el siguiente; una frase en el ledger del repo vigilado no vale;
  4. tabla ilegible: sin esquema, aridad distinta, id vacío o duplicado, o git que no contesta.
Rojo ENCLAVADO: con un fallo la línea base buena no avanza y `estado/rojo.txt` mantiene el rojo en cada corrida. Mientras está en rojo se sigue
juzgando cada commit, y cada fallo NUEVO se añade a `rojo.txt`: lo que el operador acepta al borrarlo es exactamente lo que tenía escrito
delante (hasta la última corrida en rojo, `estado/revisar.txt`); lo empujado después se juzga en la corrida siguiente.
ARRANQUE: la primera corrida fija la línea base con todo lo que hay (las lápidas, de toda la historia) y sale en ROJO a propósito: es el
simulacro del aviso y la confirmación del operador de esa línea base (no se acepta sola). Autocontenido: no importa nada del repo vigilado.
"""
import hashlib, os, subprocess, sys, time

VIGILADO = os.environ.get('VIGILADO_DIR', 'vigilado')
ESTADO = os.environ.get('ESTADO_DIR', 'estado')
TSV = 'control_plane/ai/state/reconciliacion/UNIVERSO_CAPABILITIES.tsv'
RAMA = os.environ.get('RAMA', 'master')


def git(*a):
    r = subprocess.run(['git', '-C', VIGILADO, *a], capture_output=True, text=True)
    return r.returncode, r.stdout


def tabla(texto):
    """(filas, errores). Estricto: cabecera «# Columnas:» con id, aridad exacta, id no vacío y único."""
    cols, filas, err = None, {}, []
    for n, l in enumerate(texto.splitlines(), 1):
        if l.startswith('# Columnas:'):
            cols = [c.strip() for c in l.split(':', 1)[1].strip().split('\t')]
            if 'id' not in cols:
                err.append('el esquema no tiene columna id')
        elif l.strip() and not l.startswith('#'):
            v = l.split('\t')
            if not cols or 'id' not in cols:
                err.append(f'línea {n} sin esquema válido')
                continue
            if len(v) != len(cols):
                err.append(f'línea {n}: {len(v)} campos y el esquema tiene {len(cols)}')
                continue
            f = dict(zip(cols, v))
            if not f['id'].strip():
                err.append(f'línea {n}: id vacío')
            elif f['id'] in filas:
                err.append(f'id duplicado {f["id"]}')
            else:
                filas[f['id']] = f
    if cols is None:
        err.append('sin cabecera «# Columnas:»')
    return filas, err


def sentido(f):
    f35 = (f.get('F35') or '').replace('—', 'fuera').strip()
    return '\x1f'.join([f.get('capability', '').strip(), f.get('alcance', '').strip(), f35, f.get('procedencia', '').strip(),
                        f.get('dominio', '').strip()])


def terminal(f):
    m = f.get('madurez', '')
    return m in ('ELIMINABLE', 'RETIRADA') or m.startswith('FUSIONADA')


def protegida(f):
    return f.get('procedencia') == 'OPERADOR' or f.get('dominio') == 'legal'


def huella(f):
    """Lo que aprueba el operador: ESTE sentido nuevo de la fila (128 bits), no la fila para siempre."""
    return hashlib.sha256((sentido(f) + '\x1f' + str(int(terminal(f)))).encode()).hexdigest()[:32]


def version(sha):
    rc, t = git('show', f'{sha}:{TSV}')
    if rc != 0:
        return {}, [f'git no pudo leer la tabla en {sha[:12]}']
    return tabla(t)


def comprueba(sha, filas, estado, vistos, aprob, fallos):
    """Compara UNA versión contra el estado acumulado y lo avanza (sólo se guarda si no hay fallos)."""
    for i in sorted(vistos - set(filas)):
        fallos.append(f'capability borrada en {sha[:12]}: {i} estuvo en la tabla y no está')
    for i, f in sorted(filas.items()):
        h, prot = huella(f), protegida(f)
        prev = estado.get(i)
        if prev is None:
            cambio = prot                                    # nace protegida
        else:
            cambio = (prev[0] or prot) and h != prev[1]      # protegida antes O después: cambiar de sentido, retirarse o entrar
        if cambio and (i, h) not in aprob:
            fallos.append(f'fila protegida {i} {"nace" if prev is None else "cambia de sentido, se retira o entra en protección"} en {sha[:12]} '
                          f'sin aprobación del operador en aprobaciones.tsv del testigo (si la apruebas, añade la línea «{i} {h}»)')
        estado[i] = (prot, h)
    vistos |= set(filas)


def main():
    os.makedirs(ESTADO, exist_ok=True)
    p = {k: os.path.join(ESTADO, k + x) for k, x in (('master', '.txt'), ('ids', '.txt'), ('filas', '.tsv'), ('rojo', '.txt'), ('revisar', '.txt'))}
    fallos = []
    rc, head = git('rev-parse', '--verify', f'refs/remotes/origin/{RAMA}')
    head = head.strip()
    if rc != 0 or not head:
        rc, head = git('rev-parse', '--verify', 'HEAD')
        head = head.strip()
    if rc != 0 or not head:
        fallos.append('no se puede leer el master del repo vigilado')
        head = ''
    aprob = set()
    if os.path.exists('aprobaciones.tsv'):
        aprob = {tuple(l.split()[:2]) for l in open('aprobaciones.tsv') if len(l.split()) >= 2 and not l.startswith('#')}
    rojo = open(p['rojo']).read().strip() if os.path.exists(p['rojo']) else ''
    previo = open(p['master']).read().strip() if os.path.exists(p['master']) else ''
    vistos = set(open(p['ids']).read().split()) if os.path.exists(p['ids']) else set()
    estado = {}
    if os.path.exists(p['filas']):
        for l in open(p['filas']):
            i, prot, h = l.rstrip('\n').split('\t')
            estado[i] = (prot == '1', h)
    arranque = not previo
    ahora = {}
    if rojo:
        fallos.append('rojo ENCLAVADO de una corrida anterior (cuando lo hayas revisado entero, borra estado/rojo.txt): ' + rojo.splitlines()[0][:300])
    elif os.path.exists(p['revisar']) and head and not arranque:   # el operador borró el rojo: acepta lo visto hasta la última corrida en rojo
        previo = open(p['revisar']).read().strip()
        ahora, _ = version(previo)                   # ya la revisó el operador: no se re-juzga; lo posterior, sí
        for i, f in ahora.items():
            estado[i] = (protegida(f), huella(f))
        vistos |= set(ahora)
        os.remove(p['revisar'])
    if head and arranque:
        rc, shas = git('log', '--format=%H', head, '--', TSV)
        for sha in shas.split():                     # lápidas de TODA la historia (lectura tolerante: sólo ids)
            vistos |= set(version(sha)[0])
        ahora, err = version(head)
        fallos += err
        for i in sorted(vistos - set(ahora)):
            fallos.append(f'capability borrada: {i} estuvo en la tabla y no está')
        for i, f in ahora.items():
            estado[i] = (protegida(f), huella(f))
        vistos |= set(ahora)
        fallos.append(f'ARRANQUE: línea base inicial de {len(ahora)} filas ({sum(1 for f in ahora.values() if protegida(f))} protegidas) '
                      'fijada sin revisión. Si acabas de crear el testigo, este correo es el simulacro: borra estado/rojo.txt para confirmarla')
    elif head:
        if subprocess.run(['git', '-C', VIGILADO, 'merge-base', '--is-ancestor', previo, head], capture_output=True).returncode != 0:
            fallos.append(f'historia reescrita: el master visto antes ({previo[:12]}) ya no es antepasado del actual ({head[:12]})')
            shas = [head]
        else:
            rc, out = git('log', '--format=%H', '--reverse', f'{previo}..{head}', '--', TSV)
            if rc != 0:
                fallos.append('git no pudo listar los commits desde la última corrida')
            shas = out.split() or [head]
        for sha in shas:
            ahora, err = version(sha)
            fallos += [f'{sha[:12]}: {e}' for e in err]
            comprueba(sha, ahora, estado, vistos, aprob, fallos)
    if head and (not fallos or arranque):
        with open(p['master'], 'w') as o:
            o.write(head + '\n')
        with open(p['ids'], 'w') as o:
            o.write('\n'.join(sorted(vistos)) + '\n')
        with open(p['filas'], 'w') as o:
            for i, (prot, h) in sorted(estado.items()):
                o.write(f'{i}\t{int(prot)}\t{h}\n')
    if fallos:
        ya = set(rojo.splitlines())
        nuevos = [x[:400] for x in fallos if not x.startswith('rojo ENCLAVADO') and x[:400] not in ya]
        if nuevos:                                  # se AÑADE: el rojo describe todo lo visto, no sólo el primer fallo
            with open(p['rojo'], 'a') as o:
                o.write(''.join(x + '\n' for x in nuevos))
        if head:
            with open(p['revisar'], 'w') as o:      # lo que aceptará el operador al borrar el rojo
                o.write(head + '\n')
    with open(os.path.join(ESTADO, 'registro.tsv'), 'a') as o:
        o.write(f'{int(time.time())}\t{os.environ.get("GITHUB_RUN_ID", "local")}\t{head}\t{len(ahora)}\t{"FALLO" if fallos else "OK"}\t'
                f'{len(fallos)} fallos\n')
    for x in fallos:
        print('✗', x)
    print(f'[testigo de forja] {"⛔ " + str(len(fallos)) + " fallos" if fallos else "OK"} · master {head[:12]} · {len(ahora)} filas · {len(vistos)} ids vistos')
    return 1 if fallos else 0


if __name__ == '__main__':
    sys.exit(main())
