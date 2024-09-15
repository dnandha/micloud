import click
import json
import logging
import os

from micloud.micloud import MiCloud
from .miotspec import MiotSpec, MIOT_STANDARD_TYPES

from urllib.request import urlretrieve


@click.group()
@click.option("-d", "--debug", is_flag=True)
@click.option('--username', '-u', prompt=True, help='Your Xiaomi username.')
@click.option('--password', '-p', prompt=True, hide_input=True, confirmation_prompt=False)
@click.option('--country', '-c', default='de', help='Language code of the server to query. Default: "de"')
@click.pass_context
def cli(ctx, debug, username, password, country):
    """Tool for fetching xiaomi cloud information."""
    ctx.ensure_object(dict)
    ctx.obj['username'] = username
    ctx.obj['password'] = password
    ctx.obj['country'] = country

    level = logging.INFO
    if debug:
        level = logging.DEBUG

    logging.basicConfig(level=level)

@cli.group()
def product():
    """Commands for producs."""

@product.command("list")
@click.option("--model-ids", "-m", is_flag=True, help="Output only model ids")
@click.pass_context
def product_list(ctx, model_ids):
    """Get all available products."""
    mc = MiCloud(ctx.obj['username'], ctx.obj['password'], ctx.obj['country'])
    mc.login()
    products = mc.get_all_products()
    if model_ids:
        click.echo(",".join([prod['model'] for prod in products]))
    else:
        click.echo(json.dumps(products, indent=2, sort_keys=True))

@product.command("cats")
@click.pass_context
def product_cats(ctx):
    """Get all available product categories."""
    mc = MiCloud(ctx.obj['username'], ctx.obj['password'], ctx.obj['country'])
    mc.login()
    cats = mc.get_product_cats()
    click.echo(json.dumps(cats, indent=2, sort_keys=True))

@product.command("by-cat")
@click.option('--category', '-c', prompt=True, help='Category name')
@click.option("--model-ids", "-m", is_flag=True, help="Output only model ids")
@click.pass_context
def product_by_cat(ctx, category, model_ids):
    """Get products by category."""
    mc = MiCloud(ctx.obj['username'], ctx.obj['password'], ctx.obj['country'])
    mc.login()
    products = mc.get_product_by_cat(category)
    if model_ids:
        click.echo(",".join([prod['model'] for prod in products]))
    else:
        click.echo(json.dumps(products, indent=2, sort_keys=True))

@cli.group()
def device():
    """Commands for device."""

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
@click.option('--token', '-t', help='BLE pairing token')
@click.option('--mac', '-a', help='BLE device MAC')
@click.option('--bind-key', '-b', help='BLE bind key')
def device_add(ctx, model, token, mac, bind_key):
    """Add new device to account."""
    mc = MiCloud(ctx.obj['username'], ctx.obj['password'], ctx.obj['country'])
    mc.login()
    for mdl in model.split(","):
        resp = mc.bind(mdl, token=token, mac=mac, bind_key=bind_key)
        click.echo(json.dumps(resp, indent=2, sort_keys=True))

@device.command(name="firmware")
@click.pass_context
@click.option('--outdir', '-o', default=None, help='')
def device_firmware(ctx, outdir):
    """Fetch firmware info and optionally download."""
    mc = MiCloud(ctx.obj['username'], ctx.obj['password'], ctx.obj['country'])
    mc.login()
    devices = mc.get_devices()

    firmwares = []
    for dev in devices:
        #click.echo(dev)
        ver = mc.get_version(dev['did'])
        if ver['url']:
            firmwares += [{
                'name': dev['name'],
                'model': dev['model'],
                'firmware': ver
            }]

            if outdir:
                filename = (
                    ver['version'] + "_" +
                    ver['safe_url'].split("?")[0].split("/")[-1]
                )

                urlretrieve(ver['safe_url'], os.path.join(outdir, filename))

                if 'mcu_safe_url' in ver:
                    filename = (
                        ver['version'] + "_" +
                        ver['mcu_safe_url'].split("?")[0].split("/")[-1]
                    )
                    urlretrieve(ver['mcu_safe_url'], os.path.join(outdir, filename))
        else:
            click.echo("No url found")
    click.echo(json.dumps(firmwares, indent=2, sort_keys=True))


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
