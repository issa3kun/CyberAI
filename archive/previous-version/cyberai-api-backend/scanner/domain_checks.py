"""Resolve a target and enforce the same public-address policy for every scanner."""

import ipaddress
import socket


class UnsafeTargetError(Exception):
    """The destination could not be safely confirmed as public."""


class DomainLookupError(UnsafeTargetError):
    """The system resolver could not supply usable addresses."""

    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


def _ip_literal(hostname):
    try:
        return ipaddress.ip_address(hostname)
    except ValueError:
        return None


def _is_public(ip):
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.scope_id or ip.sixtofour or ip.teredo:
            return False
        if ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        elif ip in ipaddress.IPv6Network("64:ff9b::/96"):
            return False
    return ip.is_global and not ip.is_multicast and not ip.is_reserved


def resolve_public_addresses(hostname, port):
    """Return public numeric addresses to which a scanner may connect."""
    hostname = hostname.removesuffix(".").lower()
    if hostname == "localhost" or hostname.endswith(
        (".localhost", ".local", ".internal", ".home.arpa")
    ):
        raise UnsafeTargetError("Local or internal hostnames are not allowed.")

    literal = _ip_literal(hostname)
    if literal is not None:
        ips = [literal]
    else:
        try:
            addresses = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            no_address_errors = {socket.EAI_NONAME, getattr(socket, "EAI_NODATA", None)}
            if exc.errno in no_address_errors:
                raise DomainLookupError(
                    "no_address", "The hostname lookup returned no usable IP address."
                ) from exc
            raise DomainLookupError(
                "lookup_failed", "The hostname lookup could not be completed."
            ) from exc
        ips = list(dict.fromkeys(ipaddress.ip_address(row[4][0]) for row in addresses))

    if not ips:
        raise DomainLookupError("no_address", "The hostname lookup returned no usable IP address.")
    if any(not _is_public(ip) for ip in ips):
        raise UnsafeTargetError("The target has a non-public or disallowed IP address.")

    # Keep the existing preference for IPv4, while allowing IPv6-only targets.
    ips.sort(key=lambda ip: ip.version != 4)
    return [str(ip) for ip in ips]


def inspect_domain(hostname, port):
    """Report hostname resolution without opening a connection to the target."""
    result = {
        "hostname": hostname,
        "address_source": "ip_literal" if _ip_literal(hostname.removesuffix(".")) else "hostname_lookup",
        "addresses": [],
    }
    try:
        result["addresses"] = resolve_public_addresses(hostname, port)
    except DomainLookupError as exc:
        return {**result, "status": exc.status, "message": str(exc)}
    except UnsafeTargetError as exc:
        return {**result, "status": "blocked", "message": str(exc)}
    except OSError:
        return {**result, "status": "lookup_failed", "message": "The hostname lookup could not be completed."}

    message = (
        "The supplied IP address is public."
        if result["address_source"] == "ip_literal"
        else "The hostname resolved to public IP addresses."
    )
    return {**result, "status": "public_address", "message": message}
