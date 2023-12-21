import requests
import json
from result import Ok, Err, Result, is_ok, is_err
from argparse import ArgumentParser, Namespace
from enum import Enum
from loguru import logger
from pygments import highlight, lexers, formatters

URL: str = "https://api.syscall.sh/v1"


class Architecture(Enum):
    X86 = "x86"
    X64 = "x64"
    ARM = "arm"
    ARM64 = "arm64"


def get_convention(arch: Architecture) -> Result[dict, int]:
    response = requests.get(f"{URL}/conventions/{arch.value}")
    if not response.ok:
        return Err(response.status_code)
    return Ok(response.json())


def get_syscall(syscall: str) -> Result[dict, int]:
    response = requests.get(f"{URL}/syscalls/{syscall}")
    if not response.ok:
        return Err(response.status_code)
    return Ok(response.json())


def handle_convention() -> None:
    convention = get_convention(args.arch)
    match is_ok(convention):
        case True:
            pretty_print_json(convention.ok())
        case False:
            logger.error(f"Request failed with status code {convention.err()}")


def handle_syscall() -> None:
    convention = get_syscall(args.syscall)
    match is_ok(convention):
        case True:
            syscall_of_arch = next(
                (
                    map
                    for map in convention.ok()
                    if "arch" in map and map["arch"] == args.arch.value
                ),
                None
            )
            if syscall_of_arch is None:
                logger.error(f"{args.arch.value} has no syscall '{args.syscall}'")
                return
            pretty_print_json(syscall_of_arch)
        case False:
            logger.error(f"Request failed with status code {convention.err()}")


def pretty_print_json(data: dict) -> None:
    formatted_json = json.dumps(data, sort_keys=True, indent=4)
    colorful_json = highlight(
        formatted_json, lexers.JsonLexer(), formatters.TerminalFormatter()
    )
    print(colorful_json)


def get_parser() -> ArgumentParser:
    parser = ArgumentParser(description="Get information about syscalls")
    parser.add_argument(
        "-a",
        "--arch",
        required=False,
        dest="arch",
        action="store",
        type=Architecture,
        help="Specify the architecture",
    )
    parser.add_argument(
        "-c",
        "--conv",
        required=False,
        dest="conv",
        action="store_true",
        help="Get information about calling conventions for a specific architecture",
    )
    parser.add_argument(
        "-s",
        "--syscall",
        required=False,
        dest="syscall",
        action="store",
        type=str,
        help="Get information about a syscall for a specific architecture",
    )
    return parser


if __name__ == "__main__":
    parser = get_parser()
    args = parser.parse_args()
    if args.conv:
        handle_convention()
    if args.syscall:
        handle_syscall()
