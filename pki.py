#!/usr/bin/env python

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID
from cryptography.x509.oid import NameOID

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
# signing cert (extract DN)
# signing key
# cert template
@click.argument('hostnames', nargs=-1, required=True)
@click.pass_context
def hostkeycert(ctx, hostnames):
    sign_key = load_key(CA_KEY_PEM)
    sign_cert = load_cert(CA_CRT_PEM)
    private_key = create_key()
    cert = new_certificate(
        private_key.public_key(),
        sign_key,
        sign_cert,
        hostnames,
        365, # days
    )
    write_key(private_key, KEY_PEM)
    write_cert(cert, CRT_PEM)


@cli.command()
@click.pass_context
def config(ctx):
    if 'config' in ctx.obj:
        print(yaml.dump(ctx.obj['config']))
    else:
        print('no config')


@cli.command()
def newkey():
    key = create_key()
    write_key(key, KEY_PEM)


@cli.command()
def readkey():
    load_key(KEY_PEM)


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


def load_cert(filename):
    with open(filename, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())

def write_cert(cert, filename):
    with open(filename, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

def load_key(filename):
    with open(filename, "rb") as f:
        return serialization.load_pem_private_key(
            f.read(),
            password=None,
        )

def write_key(key, filename):
    with open(filename, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))

def load_csr(filename):
    with open(filename, "rb") as f:
        return x509.load_pem_x509_csr(f.read())

def create_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )


def new_certificate(pub_key, sign_key, sign_cert, hostnames, valid_days):
    one_day = datetime.timedelta(1, 0, 0)
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Colorado"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Colorado Springs"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Elfwerks"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"Stoneglen"),
        x509.NameAttribute(NameOID.COMMON_NAME, hostnames[0])
    ]))
    builder = builder.issuer_name(sign_cert.subject)
    builder = builder.not_valid_before(datetime.datetime.today() - one_day)
    #
    # TODO: parameterize lifetime of certificate
    #
    builder = builder.not_valid_after(datetime.datetime.today() +
                                      (one_day * valid_days))
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(pub_key)
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True, content_commitment=False,
            key_encipherment=True, data_encipherment=False,
            key_agreement=False, key_cert_sign=False, crl_sign=False,
            encipher_only=False, decipher_only=False), critical=True)
    builder = builder.add_extension(
        x509.ExtendedKeyUsage([
            ExtendedKeyUsageOID.CLIENT_AUTH,
            ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True)
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(pub_key), critical=False)
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(sign_cert.public_key()),
        critical=False)
    san = []  # <- Subject Alternative Names
    for hn in hostnames:
        san.append(x509.DNSName(hn))
    builder = builder.add_extension(
        x509.SubjectAlternativeName(san), critical=False)
    return builder.sign(
        private_key=sign_key, algorithm=hashes.SHA256())


def make_csr_builder():
    return x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Colorado"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Colorado Springs"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Elfwerks"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"Stoneglen"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"Stoneglen TEST Intermediate CA"),
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
