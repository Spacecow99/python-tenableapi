

import json
from string import Template, capwords
from dataclasses import dataclass


options_template = Template("""
@dataclass
class $class_name:
    _label: str = "$parameter_name"
    _value: str = "$parameter_value"
    # Repeats for each parameter option
    $option_labels    
    def __call__(self, *args):
        query_str = " OR ".join([f'"{x}"' for x in args])
        return f'{self._value}:({query_str})'
""")

text_template = Template("""
@dataclass
class $class_name:
    _label: str = "$parameter_name"
    _value: str = "$parameter_value"
    
    def __call__(self, text: str):
        return f'{self._value}:("{text}")'
""")

date_template = Template("""
@dataclass
class $class_name:
    _label: str = "$parameter_name"
    _value: str = "$parameter_value"
    
    def __call__(self, from_date, to_date):
        if to_date < from_date:
            raise Exception("to_date must be greater than from_date")
        return f'{_self.value}:([{from_date} TO {to_date}])'
""")


def main():
    filename = "search_parameters.json"
    with open(filename, 'r') as f:
        j = json.load(f)

    print("from dataclasses import dataclass")

    for parameter in j.values():
        parameter_label = parameter["label"].replace("&", "and").replace(":", "")
        parameter_value = parameter["value"]
        class_name = parameter_label.replace(" ", "").replace("-", "")

        if parameter["type"] == "options":
            options = []
            for option in parameter["options"].values():
                option_name = option["label"].replace("&", "and").replace(":", "").replace("-", "_").replace(".", "")
                option_value = option["value"]
                options.append(f'{option_name.replace(" ", "_").lower()}: str = str("{str(option_value).replace('"', '')}")\n')
            options_str = "    ".join(options)
            print(options_template.substitute(
                class_name=class_name,
                parameter_name = parameter_label,
                parameter_value = parameter_value,
                option_labels = options_str
            ))

        elif parameter["type"] == "text":
            print(text_template.substitute(
                class_name = class_name,
                parameter_name = parameter_label,
                parameter_value = parameter_value
            ))
        
        elif parameter["type"] == "date":
            print(date_template.substitute(
                class_name=class_name,
                parameter_name=parameter_label,
                parameter_value=parameter_value
            ))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("")