#!/usr/bin/env python

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import click
import datetime
import sys
import yaml

CA_CRT_PEM = "./tmp/rootca.pem"
CA_KEY_PEM = "./tmp/rootca-key.pem"
KEY_PEM = "./tmp/key.pem"
CSR_PEM = "./tmp/csr.pem"
CRT_PEM = "./tmp/cert.pem"

DEFAULT_CONFIG = {
    "pki-dir": "pki",
    "sign-key": "ca-key.pem",
}


@click.group()
@click.option('-c', '--config',
              default="pypki.yml",
              type=click.Path(file_okay=True, readable=True, allow_dash=False))
@click.pass_context
def cli(ctx, config):
    ctx.ensure_object(dict)
    if config != None:
        with open(config) as f:
            ctx.obj['config_file'] = config
            ctx.obj['config'] = yaml.load(f, Loader=yaml.FullLoader)
    pass

@cli.command()
def debug():
    print("debug")

@cli.command()
@click.pass_context
def config(ctx):
    if 'config' in ctx.obj:
        print(yaml.dump(ctx.obj['config']))
    else:
        print('no config')


@cli.command()
def newkey():
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    with open(KEY_PEM, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))

@cli.command()
def readkey():
    with open(KEY_PEM, "rb") as f:
        key = serialization.load_pem_private_key(
            f.read(),
            password=None,
        )

@cli.command()
def csr():
    key = load_key(KEY_PEM)
    csr_builder = make_csr_builder()
    csr = csr_builder.sign(key, hashes.SHA256())
    with open(CSR_PEM, "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))


@cli.command()
def signcsr():
    cakey = load_key(CA_KEY_PEM)
    cacert = load_cert(CA_CRT_PEM)
    csr = load_csr(CSR_PEM)
    cert = x509.CertificateBuilder().subject_name(
        csr.subject
    ).issuer_name(
        cacert.subject
    ).public_key(
        csr.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=10)
    ).sign(cakey, hashes.SHA256())
    with open(CRT_PEM, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def load_cert(pem_file):
    with open(pem_file, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())

def load_key(pem_file):
    with open(pem_file, "rb") as f:
        return serialization.load_pem_private_key(
            f.read(),
            password=None,
        )

def load_csr(pem_file):
    with open(pem_file, "rb") as f:
        return x509.load_pem_x509_csr(f.read())

def make_csr_builder():
    return x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Colorado"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Colorado Springs"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Elfwerks"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"Stoneglen"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Stoneglen TEST Intermediate CA"),
    ]))


def load_config():
    config = {
        "pki-dir": "./pki",
        "sign-key": "ca-key.pem",
    }
    return config


def main():
    config = load_config()
    cli()


if __name__ == '__main__':
    sys.exit(main())
