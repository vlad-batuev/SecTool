import uuid
import json
import argparse
from pathlib import Path
from collections import Counter


class Sbom:
    def __init__(self, project_path, exclude_dir=None):
        self.project_path = project_path
        self.exclude_dir = exclude_dir
        self.bom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "components": []
        }

    def __call__(self):
        language = self.searcher_language()
        match language:
            case 'Python':
                components = self.sbom_for_python()
                self.bom['components'] = components
                self.save_bom_to_json()
            case 'JavaScript':
                components = self.sbom_for_javascript()
                self.bom['components'] = components
                self.save_bom_to_json()
            case 'Java':
                print('Java')
            case 'C++':
                print('C++')
            case 'C':
                print('C')
            case 'Ruby':
                print('Ruby')
            case 'PHP':
                print('PHP')
            case 'Go':
                components = self.sbom_for_go()
                self.bom['components'] = components
                self.save_bom_to_json()
            case 'Swift':
                print('Swift')
            case 'Kotlin':
                print('Kotlin')

    def sbom_for_python(self):
        def find_requirements_file(project_path):
            path = Path(project_path)
            requirements_file = path.rglob('requirements.txt')
            for file in requirements_file:
                return file
            return None

        components = []
        requirements_file = find_requirements_file(self.project_path)

        if requirements_file is None:
            print("Файл requirements.txt не найден.")
            return components

        with open(requirements_file, 'r') as file:
            for line in file:
                line = line.strip()
                if line and not line.startswith('#'):
                    parts = line.split('==')
                    name = parts[0].strip()
                    version = parts[1].strip() if len(parts) > 1 else None
                    components.append({"name": name, "version": version})

        return components

    def sbom_for_go(self):
        def find_go_mod_file(project_path):
            path = Path(project_path)
            go_mod_file = path.rglob('go.mod')
            for file in go_mod_file:
                return file
            return None

        components = []
        go_mod_file = find_go_mod_file(self.project_path)

        if go_mod_file is None:
            print("Файл go.mod не найден.")
            return components

        with open(go_mod_file, 'r') as file:
            for line in file:
                line = line.strip()
                if line.startswith("require"):
                    parts = line.split()
                    if len(parts) >= 3:
                        name = parts[1].strip('"')
                        version = parts[2].strip('"')
                        components.append({"name": name, "version": version})

        return components

    def sbom_for_javascript(self):
        def find_package_json(project_path):
            path = Path(project_path)
            package_json_file = path.rglob('package.json')
            for file in package_json_file:
                return file
            return None

        components = []
        package_json_file = find_package_json(self.project_path)

        if package_json_file is None:
            print("Файл package.json не найден.")
            return components

        with open(package_json_file, 'r') as file:
            data = json.load(file)
            dependencies = data.get("dependencies", {})
            for name, version in dependencies.items():
                components.append({"name": name, "version": version})

        return components

    def searcher_language(self):
        language_map = {
            '.py': 'Python',
            '.js': 'JavaScript',
            '.java': 'Java',
            '.cpp': 'C++',
            '.c': 'C',
            '.rb': 'Ruby',
            '.php': 'PHP',
            '.go': 'Go',
            '.sh': 'Shell Script',
            '.swift': 'Swift',
            '.kt': 'Kotlin',
        }

        language_counter = Counter()

        for file in Path(self.project_path).rglob('*'):
            if file.is_file():
                ext = file.suffix
                if ext in language_map:
                    language_counter[language_map[ext]] += 1

        if language_counter:
            most_common_language = language_counter.most_common(1)[0][0]
            return most_common_language
        else:
            return None

    def save_bom_to_json(self):
        output_filename = Path(self.project_path) / 'sbom.json'

        with open(output_filename, 'w') as json_file:
            json.dump(self.bom, json_file, indent=4)

        print(f"СБОМ сохранен в {output_filename}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument('--path', type=Path, required=True)
    parser.add_argument('--exclude_dir', type=str, default=None)

    args = parser.parse_args()

    sbom_gen = Sbom(
        project_path=args.path,
        exclude_dir=args.exclude_dir
    )
    sbom_gen()
