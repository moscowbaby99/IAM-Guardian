import yaml
import argparse
import sys

class IAMGuardian:
    def __init__(self, file_path):
        self.file_path = file_path
        self.findings = []

    def load_yaml(self):
        """Загружает и парсит YAML файл."""
        try:
            with open(self.file_path, 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            print(f"[!] Ошибка: Файл '{self.file_path}' не найден.")
            sys.exit(1)
        except yaml.YAMLError as e:
            print(f"[!] Ошибка синтаксиса YAML: {e}")
            sys.exit(1)

    def analyze_policy(self, policy):
        """Анализирует структуру политик на наличие уязвимостей."""
        # Получаем список Statement. Если он один (не в списке), оборачиваем в список.
        statements = policy.get('Statement', [])
        if not isinstance(statements, list):
            statements = [statements]

        for idx, statement in enumerate(statements, 1):
            sid = statement.get('Sid', f'Unlabeled-{idx}')
            effect = statement.get('Effect', '')
            
            # Нас интересуют только разрешающие правила
            if effect != 'Allow':
                continue

            actions = statement.get('Action', [])
            if isinstance(actions, str):
                actions = [actions]

            resources = statement.get('Resource', [])
            if isinstance(resources, str):
                resources = [resources]

            # Проверка на полное отсутствие ограничений по действиям (Admin rights)
            if '*' in actions:
                self.findings.append(f"[{sid}] Критическая угроза: Разрешены любые действия (Action: '*')")

            # Проверка на доступ ко всем ресурсам
            if '*' in resources:
                self.findings.append(f"[{sid}] Высокий риск: Доступ ко всем ресурсам (Resource: '*')")

    def run(self):
        """Запуск линтера."""
        print(f"[*] Сканирование файла: {self.file_path}...\n")
        policy = self.load_yaml()
        
        if not policy or 'Statement' not in policy:
            print("[?] В файле не найдено блоков 'Statement'. Пропуск.")
            return True

        self.analyze_policy(policy)

        if self.findings:
            print("[!] НАЙДЕНЫ ОПАСНЫЕ КОНФИГУРАЦИИ:")
            for finding in self.findings:
                print(f"  -> {finding}")
            return False
        else:
            print("[+] Конфигурация выглядит безопасно. Wildcards не обнаружены.")
            return True

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="IAM Guardian: Линтер для поиска опасных привилегий в YAML.")
    parser.add_argument("file", help="Путь к YAML файлу с политиками")
    args = parser.parse_args()

    scanner = IAMGuardian(args.file)
    is_secure = scanner.run()
    
    # Если найдены угрозы, возвращаем код ошибки (нужно для блокировки CI/CD пайплайна)
    if not is_secure:
        sys.exit(1)
    else:
        sys.exit(0)