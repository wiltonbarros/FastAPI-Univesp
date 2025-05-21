import psycopg2
from dotenv import load_dotenv
import os
from contextlib import contextmanager

load_dotenv() # Esta linha agora está ativa!

DATABASE = os.getenv("DATABASE")
HOST = os.getenv("HOST")
USERSERVER = os.getenv("USERSERVER")
PASSWORD = os.getenv("PASSWORD")
PORT = os.getenv("PORT")

@contextmanager
def instance_cursor():
    connection = psycopg2.connect(database = DATABASE, host = HOST, user = USERSERVER, password = PASSWORD, port = PORT)
    cursor = connection.cursor()
    try:
        yield cursor
        connection.commit() # Adicionar commit para salvar alterações se houver
    finally:
        if connection:
            cursor.close()
            connection.close()
            # print('Conexão finalizada') # Opcional: remova esta linha em produção

def get_user_from_db(username: str):
    """
    Consulta o banco de dados para obter um usuário pelo nome de usuário.
    Retorna um dicionário com os dados do usuário ou None se não encontrado.
    """
    with instance_cursor() as cursor:
        query = '''
            SELECT username, full_name, email, hashed_password, disabled
            FROM public."Users"
            WHERE username = %s;
            '''
        # O segundo argumento de execute DEVE ser uma tupla, mesmo que seja um único valor.
        cursor.execute(query, (username,))
        row = cursor.fetchone() # Use fetchone() para um único resultado esperado

        if row:
            # Mapeia os dados da tupla para um dicionário, que UserInDB pode usar.
            return {
                "username": row[0],
                "full_name": row[1],
                "email": row[2],
                "hashed_password": row[3],
                "disabled": row[4]
            }
        return None # Retorna None se o usuário não for encontrado

def consulta_All():
    """
    Consulta todos os usuários do banco de dados.
    (Esta função não é usada diretamente na autenticação de login, mas foi corrigida).
    """
    with instance_cursor() as cursor:
        query = '''
            SELECT username, full_name, email, hashed_password, disabled
            FROM public."Users";
            '''
        cursor.execute(query)
        # Retorna uma lista de tuplas para todos os usuários
        return cursor.fetchall()