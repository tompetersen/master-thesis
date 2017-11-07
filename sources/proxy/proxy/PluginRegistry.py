import inspect
import os
from importlib import machinery, util

from proxy.AbstractPlugin import AbstractPlugin


class PluginNotFoundError(Exception):
    pass


class PluginRegistry:
    """
    TBD

    Details can be found here:
    - https://chriscoughlin.com/2012/04/writing-a-python-plugin-framework/
    - https://stackoverflow.com/questions/35288021/what-is-the-equivalent-of-imp-find-module-in-importlib
    - https://docs.python.org/3/library/importlib.html
    """

    def __init__(self, plugin_path: str):
        self._load_plugins(plugin_path)

    def _load_plugins(self, plugin_path: str):
        self._plugins = {}
        print('Loading plugins from [%s]...' % plugin_path)
        for plugin_file in os.listdir(plugin_path):
            plugin_file_path = os.path.join(plugin_path, plugin_file)
            module_name, module_extension = os.path.splitext(plugin_file)
            if module_extension == os.extsep + "py":
                try:
                    plugin_spec = util.spec_from_file_location(module_name, plugin_file_path)
                    plugin_module = util.module_from_spec(plugin_spec)
                    plugin_spec.loader.exec_module(plugin_module)

                    plugin_classes = inspect.getmembers(plugin_module, inspect.isclass) # gives (name, class) tupels
                    for member_class in plugin_classes:
                        cls = member_class[1]
                        name = member_class[0]
                        if issubclass(cls, AbstractPlugin) and (cls.__module__ != AbstractPlugin.__module__):
                            print("\tLoaded plugin: " + name)
                            self._plugins[name] = cls() # TODO: Instantiating plugin instance here or in alter_data?
                except Exception:
                    # TODO: error handling for plugin loading
                    raise
        print('')

    def has_plugin_with_name(self, plugin_name: str) -> bool:
        return plugin_name in self._plugins

    def alter_data(self, plugin_name: str, data: str, **kwargs) -> str:
        if self.has_plugin_with_name(plugin_name):
            plugin = self._plugins[plugin_name]
            return plugin.handle_data(data, **kwargs)
        else:
            raise PluginNotFoundError('No plugin found for name [%s]' % plugin_name)
