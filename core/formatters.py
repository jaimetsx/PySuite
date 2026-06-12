from rich.table import Table

def build_key_value_table(title: str, data: dict) -> Table:
    table = Table(title=title, header_style="bold cyan")
    table.add_column("Field", style="green")
    table.add_column("Value", style="white")

    for key, value in data.items():
        table.add_row(str(key), str(value))

    return table