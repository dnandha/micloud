import click
import json
import logging
import os

from micloud.micloud import MiCloud
from .miotspec import MiotSpec, MIOT_STANDARD_TYPES

from urllib.request import urlretrieve


@click.group()
@click.option("-d", "--debug", is_flag=True)
def cli(debug):
    """Tool for fetching xiaomi cloud information."""
    level = logging.INFO
    if debug:
        level = logging.DEBUG

    logging.basicConfig(level=level)

@cli.group()
@click.option('--username', '-u', prompt=True, help='Your Xiaomi username.')
@click.option('--password', '-p', prompt=True, hide_input=True, confirmation_prompt=False)
@click.option('--country', '-c', default='de', help='Language code of the server to query. Default: "de"')
@click.pass_context
def device(ctx, username, password, country):
    """Commands for device."""
    ctx.ensure_object(dict)
    ctx.obj['username'] = username
    ctx.obj['password'] = password
    ctx.obj['country'] = country


@device.command(name="list")
@click.pass_context
def device_list(ctx):
    """Get device information, including tokens."""
    mc = MiCloud(ctx.obj['username'], ctx.obj['password'], ctx.obj['country'])
    mc.login()
    devices = mc.get_devices()
    click.echo(json.dumps(devices, indent=2, sort_keys=True))

@device.command(name="delete-all")
@click.pass_context
def device_delete_all(ctx):
    """Delete all devices from account."""
    mc = MiCloud(ctx.obj['username'], ctx.obj['password'], ctx.obj['country'])
    mc.login()
    devices = mc.get_devices()
    for dev in devices:
        resp = mc.delete(dev['did'], dev['pid'])
        click.echo(json.dumps(resp, indent=2, sort_keys=True))

@device.command(name="add")
@click.pass_context
@click.option('--model', '-m', prompt=True, help='Device model')
def device_add(ctx, model):
    """Add new device to account."""
    mc = MiCloud(ctx.obj['username'], ctx.obj['password'], ctx.obj['country'])
    mc.login()
    for mdl in model.split(","):
        resp = mc.bind(mdl)
        click.echo(json.dumps(resp, indent=2, sort_keys=True))

@device.command(name="firmware")
@click.pass_context
@click.option('--outdir', '-o', default=None, help='')
def device_firmware(ctx, outdir):
    """Fetch firmware info and optionally download."""
    mc = MiCloud(ctx.obj['username'], ctx.obj['password'], ctx.obj['country'])
    mc.login()
    devices = mc.get_devices()
    for dev in devices:
        click.echo(dev['name'])
        ver = mc.get_version(dev['did'])
        click.echo(json.dumps(ver, indent=2, sort_keys=True))

        if ver['url'] and outdir:
            filename = (
                ver['version'] + "_" +
                ver['url'].split("?")[0].split("/")[-1]
            )

            res = urlretrieve(ver['url'], os.path.join(outdir, filename))
            if res:
                click.echo("Download successful")
            else:
                click.echo("Download failed")
        else:
            click.echo("Skipped download")


@cli.group()
def miot():
    """Commands for miotspec fetching."""


@miot.command(name="specs")
@click.option("--status", type=str, default="released")
def miot_specs(status):
    """Return all specs filtered by the given status."""
    click.echo(json.dumps(MiotSpec.get_specs(status=status)))


@miot.command(name="get-spec")
@click.argument("urn")
def miot_get_spec(urn):
    """Return a device spec for the given URN."""
    click.echo(json.dumps(MiotSpec.get_spec_for_urn(urn)))


@miot.command("types")
@click.argument("type", type=click.Choice(MIOT_STANDARD_TYPES))
def miot_available_standard_types(type: str):
    """Return available standard URNs for type. """
    click.echo(json.dumps(MiotSpec.get_standard_types(type)))


@miot.command("get-type-spec")
@click.argument("urn", required=False)
def miot_get_standard_type_spec(urn: str):
    """Return a type spec for given type URN."""
    click.echo(json.dumps(MiotSpec.get_standard_type_spec(urn)))

if __name__ == "__main__":
    cli()
