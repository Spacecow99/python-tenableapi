#!/usr/bin/env python3

"""
CLI application entry point for tenable_api.

A wrapper around the tenable.com public API.
"""

import argparse
import json

from tenable_api import __version__
from tenable_api.attack_path_techniques import AttackPathTechniques
from tenable_api.audits import Audits
from tenable_api.cve import CVE
from tenable_api.indicators import Indicators
from tenable_api.plugins import Plugins


def main():
    parser = argparse.ArgumentParser(prog="tenable_api")
    parser.add_argument("--version", action="version", version=f"{__version__}")
    subparsers = parser.add_subparsers(
        dest="api", description="APIs to invoke", help='subcommand help')

    ## Attack Path Techniques CLI parser
    #############################################################################
    attack_path_techniques = subparsers.add_parser(
        "attack_path_techniques", help="Attack Path Techniques",
        description="Attack Path Techniques"
    )
    apt_subparsers = attack_path_techniques.add_subparsers(
        dest="endpoint", help='subcommand help',
        description="Subcommands for attack path techniques"
    )
    # `tenable_api attack_path_techniques all` subparser
    apt_all = apt_subparsers.add_parser(
        "all", help="Get all attack path techniques"
    )
    apt_all.add_argument(
        "page", type=int, default=1, help="Page number to query"
    )
    # `tenable_api attack_path_techniques search` subparser
    apt_search = apt_subparsers.add_parser(
        "search", help="Search for attack path techniques"
    )
    apt_search.add_argument(
        "q", type=str, help="Search query"
    )
    apt_search.add_argument(
        "page", type=int, default=1, help="Page number to query"
    )
    apt_search.add_argument(
        "sort", type=str, default="", help="Sort by"
    )

    ## Audits CLI parser
    #############################################################################
    audits = subparsers.add_parser("audits", help="Audits")
    audits_subparsers = audits.add_subparsers(
        dest="endpoint", help='subcommand help',
        description="Subcommands for audits"
    )
    # `tenable_api audits all` subparser
    audits_all = audits_subparsers.add_parser("all", help="Get all audits")
    audits_all.add_argument(
        "page", type=int, default=1, help="Page number to query"
    )
    # `tenable_api audits newest` subparser
    audits_newest = audits_subparsers.add_parser(
        "newest", help="Get newest audits"
    )
    audits_newest.add_argument(
        "page", type=int, default=1, help="Page number to query"
    )
    # `tenable_api audits updates` subparser
    audits_updates = audits_subparsers.add_parser(
        "updates", help="Get updated audits"
    )
    audits_updates.add_argument(
        "page", type=int, default=1, help="Page number to query"
    )
    # `tenable_api audits search` subparser
    audits_search = audits_subparsers.add_parser(
        "search", help="Search for audits"
    )
    audits_search.add_argument(
        "q", type=str, help="Search query"
    )
    audits_search.add_argument(
        "page", type=int, default=1, help="Page number to query"
    )
    # `tenable_api audits references` subparser
    audits_references = audits_subparsers.add_parser(
        "references", help="Get references"
    )
    audits_references.add_argument(
        "page", type=int, default=1, help="Page number to query"
    )
    # `tenable_api audits authorities` subparser
    audits_authorities = audits_subparsers.add_parser(
        "authorities", help="Get authorities"
    )
    audits_authorities.add_argument(
        "page", type=int, default=1, help="Page number to query"
    )

    # CVE CLI parser
    #############################################################################
    cve = subparsers.add_parser("cve", help="CVE")
    cve_subparsers = cve.add_subparsers(
        dest="endpoint", help='subcommand help',
        description="Subcommands for CVE"
    )
    # `tenable_api cve all` subparser
    cve_all = cve_subparsers.add_parser("all", help="Get all CVEs")
    cve_all.add_argument(
        "page", type=int, default=1, help="Page number to query"
    )
    # `tenable_api cve newest` subparser
    cve_newest = cve_subparsers.add_parser("newest", help="Get newest CVEs")
    cve_newest.add_argument(
        "page", type=int, default=1, help="Page number to query"
    )
    # `tenable_api cve updated` subparser
    cve_updated = cve_subparsers.add_parser("updated", help="Get updated CVEs")
    cve_updated.add_argument(
        "page", type=int, default=1, help="Page number to query"
    )
    # `tenable_api cve search` subparser
    cve_search = cve_subparsers.add_parser("search", help="Search for CVEs")
    cve_search.add_argument(
        "q", type=str, help="Search query"
    )
    cve_search.add_argument(
        "page", type=int, default=1, help="Page number to query"
    )
    # `tenable_api cve cve` subparser
    cve_cve = cve_subparsers.add_parser("cve", help="Get CVE by ID")
    cve_cve.add_argument(
        "cve_id", type=str, help="CVE ID"
    )
    # `tenable_api cve plugins` subparser
    cve_plugins = cve_subparsers.add_parser(
        "plugins", help="Get CVE related plugins"
    )
    cve_plugins.add_argument(
        "cve_id", type=str, help="CVE ID"
    )

    # Indicators CLI parser
    #############################################################################
    indicators = subparsers.add_parser("indicators", help="Indicators")
    indicators_subparsers = indicators.add_subparsers(
        dest="endpoint", help='subcommand help',
        description="Subcommands for indicators"
    )
    # `tenable_api indicators search` subparser
    indicators_search = indicators_subparsers.add_parser(
        "search", help="Search for indicators"
    )
    indicators_search.add_argument(
        "q", type=str, help="Search query"
    )
    indicators_search.add_argument(
        "page", type=int, default=1, help="Page number to query"
    )
    # `tenable_api indicators ioa` subparser
    indicators_ioa = indicators_subparsers.add_parser(
        "ioa", help="Get indicators of attack"
    )
    indicators_ioa.add_argument(
        "page", type=int, default=1, help="Page number to query"
    )
    # `tenable_api indicators ioe` subparser
    indicators_ioe = indicators_subparsers.add_parser(
        "ioe", help="Get indicators of exposure"
    )
    indicators_ioe.add_argument(
        "page", type=int, default=1, help="Page number to query"
    )

    # Plugins CLI parser
    #############################################################################
    plugins = subparsers.add_parser("plugins", help="Plugins")
    plugins_subparsers = plugins.add_subparsers(
        dest="endpoint", help='subcommand help',
        description="Subcommands for plugins"
    )
    # `tenable_api plugins all` subparser
    plugins_all = plugins_subparsers.add_parser("all", help="Get all plugins")
    plugins_all.add_argument(
        "page", type=int, default=1, help="Page number to query"
    )
    plugins_all.add_argument(
        "sort", type=str, default="", help="Sort by"
    )
    # `tenable_api plugins newest` subparser
    plugins_newest = plugins_subparsers.add_parser(
        "newest", help="Get newest plugins"
    )
    plugins_newest.add_argument(
        "page", type=int, default=1, help="Page number to query"
    )
    # `tenable_api plugins updated` subparser
    plugins_updated = plugins_subparsers.add_parser(
        "updated", help="Get updated plugins"
    )
    plugins_updated.add_argument(
        "page", type=int, default=1, help="Page number to query"
    )
    # `tenable_api plugins families` subparser
    plugins_families = plugins_subparsers.add_parser(
        "families", help="Get plugin families"
    )
    plugins_families.add_argument(
        "type", type=str, help="Type of plugin families"
    )
    # `tenable_api plugins family` subparser
    plugins_family = plugins_subparsers.add_parser(
        "family", help="Get plugin family"
    )
    plugins_family.add_argument(
        "type", type=str, help="Type of plugin family"
    )
    plugins_family.add_argument(
        "family", type=str, help="Plugin family"
    )
    plugins_family.add_argument(
        "page", type=int, default=1, help="Page number to query"
    )
    # `tenable_api plugins plugin` subparser
    plugins_plugin = plugins_subparsers.add_parser("plugin", help="Get plugin")
    plugins_plugin.add_argument(
        "family", type=str, help="Plugin family"
    )
    plugins_plugin.add_argument(
        "plugin_id", type=str, help="Plugin ID"
    )
    # `tenable_api plugins search` subparser
    plugins_search = plugins_subparsers.add_parser(
        "search", help="Search for plugins"
    )
    plugins_search.add_argument(
        "q", type=str, help="Search query"
    )
    plugins_search.add_argument(
        "page", type=int, default=1, help="Page number to query"
    )

    args = parser.parse_args()

    # Parse attack path techniques arguments
    if args.api == "attack_path_techniques":
        endpoint = AttackPathTechniques()
        if args.endpoint == "all":
            print(json.dumps(endpoint.all(args.page), indent=4))
        elif args.endpoint == "search":
            print(json.dumps(
                endpoint.search(args.q, args.page, args.sort), indent=4
            ))
        else:
            parser.print_help()
            return

    # Parse audits arguments
    elif args.api == "audits":
        endpoint = Audits()
        if args.endpoint == "all":
            print(json.dumps(endpoint.all(args.page), indent=4))
        elif args.endpoint == "newest":
            print(json.dumps(endpoint.newest(args.page), indent=4)) 
        elif args.endpoint == "updates":
            print(json.dumps(endpoint.updates(args.page), indent=4))
        elif args.endpoint == "search":
            print(json.dumps(endpoint.search(args.q, args.page), indent=4))
        elif args.endpoint == "references":
            print(json.dumps(endpoint.references(args.page), indent=4))
        elif args.endpoint == "authorities":
            print(json.dumps(endpoint.authorities(args.page), indent=4))
        else:
            parser.print_help()
            return

    # Parse CVE arguments
    elif args.api == "cve":    
        endpoint = CVE()
        if args.endpoint == "all":
            print(json.dumps(endpoint.all(args.page), indent=4))
        elif args.endpoint == "newest":
            print(json.dumps(endpoint.newest(args.page), indent=4))
        elif args.endpoint == "updated":
            print(json.dumps(endpoint.updated(args.page), indent=4))
        elif args.endpoint == "search":
            print(json.dumps(endpoint.search(args.q, args.page), indent=4))
        elif args.endpoint == "cve":
            print(json.dumps(endpoint.cve(args.cve_id), indent=4))
        elif args.endpoint == "plugins":
            print(json.dumps(endpoint.plugins(args.cve_id), indent=4))
        else:
            parser.print_help()
            return

    # Parse indicators arguments
    elif args.api == "indicators":
        endpoint = Indicators()
        if args.endpoint == "search":
            print(json.dumps(endpoint.search(args.q, args.page), indent=4))
        elif args.endpoint == "ioa":
            print(json.dumps(endpoint.ioa(args.page), indent=4))
        elif args.endpoint == "ioe":
            print(json.dumps(endpoint.ioe(args.page), indent=4))
        else:
            parser.print_help()
            return

    # Parse plugins arguments
    elif args.api == "plugins":
        endpoint = Plugins()
        if args.endpoint == "all":
            print(json.dumps(endpoint.all(args.page, args.sort), indent=4))
        elif args.endpoint == "newest":
            print(json.dumps(endpoint.newest(args.page), indent=4))
        elif args.endpoint == "updated":
            print(json.dumps(endpoint.updated(args.page), indent=4))
        elif args.endpoint == "families":
            print(json.dumps(endpoint.families(args.type), indent=4))
        elif args.endpoint == "family":
            print(json.dumps(
                endpoint.family(args.type, args.family, args.page), indent=4
            ))
        elif args.endpoint == "plugin":
            print(json.dumps(
                endpoint.plugin(args.family, args.plugin_id), indent=4
            ))
        elif args.endpoint == "search":
            print(json.dumps(endpoint.search(args.q, args.page), indent=4))

    else:
        parser.print_help()
        return


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("")

