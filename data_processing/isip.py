def is_ipv4_without_mask(ip: str) -> bool:
    ip = ip.split('.')
    try:
        ip = [int(i) for i in ip]
    except (ValueError, TypeError):
        return False
    else:
        if len(ip) != 4:
            return False
        for octet in ip:
            if not (0 <= octet <= 255):
                return False
        return True
        
## Checks if address is IPv4 with mask in /x or y.y.y.y format
def is_ipv4_with_mask(address: str) -> bool:
    if '/' in address:
        ip = address.split('/')[0]
        mask = address.split('/')[-1]
        try:
            mask = int(mask)
        except (ValueError, TypeError):
            return False
        else:
            if mask > 32:
                return False
    elif ' ' in address:
        ip = address.split()[0]
        mask = address.split()[-1]
        mask = mask.split('.')
        if len(mask) != 4:
            return False
        else:
            try:
                mask = [int(m) for m in mask]
            except (ValueError, TypeError):
                return False
            else:
                for i in range(3):
                    if (
                        mask[i] < mask[i+1]
                        or not (0 <= mask[i] <= 255)
                        or not (0 <= mask[i+1] <= 255)
                    ):
                        return False
    else:
        return False
    return is_ipv4_without_mask(ip)

