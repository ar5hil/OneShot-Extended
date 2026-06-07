from rich.console import Console
from rich.theme import Theme

_STYLES = {
    'info': 'bold',
    'success': 'bold green',
    'warning': 'bold yellow',
    'error': 'bold red',
}

_THEME = Theme({
    'info': 'bold',
    'success': 'bold green',
    'warning': 'bold yellow',
    'error': 'bold red',
})

_CONSOLE = Console(theme=_THEME, highlight=False)

def _log(style: str, prefix: str, message: str):
    _CONSOLE.print(f'{prefix} {message}', style=style)

def info(message: str):
    _log('info', '[*]', message)

def success(message: str):
    _log('success', '[+]', message)

def warning(message: str):
    _log('warning', '[-]', message)

def error(message: str):
    _log('error', '[!]', message)

def initializeLogging():
    pass
