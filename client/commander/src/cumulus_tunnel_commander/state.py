import sqlite3
import os

class StateManagementFunctions:

    def __init__(self, state_file_path: str, logger):
        self.logger = logger
        self.state_file_path = state_file_path
        self.conn = sqlite3.connect(database=state_file_path)
        self._prepare_state()
        self._test()

    def _prepare_state(self):
        cursor = self.conn.cursor()
        cursor.execute('SELECT name FROM sqlite_master WHERE type=\'table\';')
        records = cursor.fetchall()
        if len(records) == 0:
            self.logger.info('Creating state file: {}'.format(self.state_file_path))
            cursor.execute("CREATE TABLE IF NOT EXISTS state(state_key TEXT, state_value TEXT, PRIMARY KEY (state_key) )")

    def get_state(self, state_key: str)->str:
        cursor = self.conn.cursor()
        for row in cursor.execute('SELECT state_value FROM state WHERE state_key = ?', (state_key,)):
            return '{}'.format(row[0])
        self.conn.commit()
        cursor.close()
        
    def write_state(self, state_key: str, state_value: str):
        cursor = self.conn.cursor()
        self.delete_state(state_key=state_key)
        cursor.execute('INSERT INTO state (state_key, state_value) VALUES (?, ?)', (state_key, state_value,))
        self.conn.commit()
        cursor.close()

    def delete_state(self, state_key: str):
        cursor = self.conn.cursor()
        cursor.execute('DELETE FROM state WHERE state_key = ?', (state_key,))
        self.conn.commit()
        cursor.close()

    def _test(self):
        self.write_state(state_key='test_key', state_value='test value')
        self.write_state(state_key='test_key', state_value='test value 2')
        value = self.get_state(state_key='test_key')
        self.logger.debug('state test value: {}'.format(value))
        if value != 'test value 2':
            raise Exception('DB Basic Tests Failed')
        self.delete_state(state_key='test_key')

