import random

def es_primo(n):
    """
    Verifica si un número es primo.
    """
    if n < 2:
        return False
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            return False
    return True

def generar_primo(rango_inferior, rango_superior):
    """
    Genera un número primo aleatorio dentro de un rango dado.
    """
    primos = [num for num in range(rango_inferior, rango_superior + 1) if es_primo(num)]
    if not primos:
        return None
    return random.choice(primos)

def mcd(a, b):
    """
    Calcula el MCD de dos números usando el algoritmo de Euclides.
    """
    while b != 0:
        a, b = b, a % b
    return a

def inverso_modular(e, n):
    """
    Calcula el inverso modular de e módulo n usando el algoritmo extendido de Euclides.
    """
    t, nuevo_t = 0, 1
    r, nuevo_r = n, e

    while nuevo_r != 0:
        cociente = r // nuevo_r
        r, nuevo_r = nuevo_r, r - cociente * nuevo_r
        t, nuevo_t = nuevo_t, t - cociente * nuevo_t

    if r > 1:
        return None
    if t < 0:
        t += n
    return t

def generar_llaves(rango_inferior, rango_superior):
    """
    Genera un par de llaves pública y privada para el algoritmo RSA.
    
    Parámetros:
        rango_inferior (int): Límite inferior del rango para los números primos.
        rango_superior (int): Límite superior del rango para los números primos.
        
    Retorno:
        tuple: Una tupla con la clave pública (e, n) y la clave privada (d, n), o None si falla.
    """
    # Generar dos números primos p y q
    p = generar_primo(rango_inferior, rango_superior)
    q = generar_primo(rango_inferior, rango_superior)
    
    if not p or not q or p == q:
        return None  # Error: no se pueden generar dos números primos distintos
    
    # Calcular n y phi(n)
    n = p * q
    phi = (p - 1) * (q - 1)
    
    # Elegir e tal que 1 < e < phi y mcd(e, phi) = 1
    e = random.randint(2, phi - 1)
    while mcd(e, phi) != 1:
        e = random.randint(2, phi - 1)
    
    # Calcular d como el inverso modular de e módulo phi
    d = inverso_modular(e, phi)
    if not d or d == e:
        return None  # Error: no se pudo generar un d válido
    
    # Retornar las claves pública y privada
    clave_publica = (e, n)
    clave_privada = (d, n)
    return clave_publica, clave_privada

# Ejemplo de uso
rango_inferior = 10
rango_superior = 50

llaves = generar_llaves(rango_inferior, rango_superior)
if llaves:
    clave_publica, clave_privada = llaves
    print(f"Clave pública: {clave_publica}")
    print(f"Clave privada: {clave_privada}")
else:
    print("No se pudieron generar las llaves en el rango especificado.")

def encriptar(mensaje, clave_publica):
    """
    Encripta un mensaje usando la llave pública de RSA.
    
    Parámetros:
        mensaje (int): El caracter a encriptar, representado como un número entero M < n.
        clave_publica (tuple): La llave pública (e, n).
        
    Retorno:
        int: El caracter encriptado C.
        
    Excepciones:
        ValueError: Si el mensaje no es un número entero positivo o si no cumple M < n.
    """
    # Desempaquetar la clave pública
    e, n = clave_publica
    
    # Validar el mensaje
    if not isinstance(mensaje, int) or mensaje < 0:
        raise ValueError("El mensaje debe ser un número entero positivo.")
    if mensaje >= n:
        raise ValueError(f"El mensaje debe ser menor que n. Recibido: {mensaje}, n: {n}")
    
    # Cifrar el mensaje
    # C = M^e mod n
    caracter_encriptado = pow(mensaje, e, n)
    return caracter_encriptado

# Ejemplos de uso
clave_publica_1 = (7, 221)
mensaje_1 = 42
print(f"Encriptar({mensaje_1}, {clave_publica_1}) = {encriptar(mensaje_1, clave_publica_1)}")  # Salida esperada: 196

clave_publica_2 = (5, 899)
mensaje_2 = 15
print(f"Encriptar({mensaje_2}, {clave_publica_2}) = {encriptar(mensaje_2, clave_publica_2)}")  # Salida esperada: 759




