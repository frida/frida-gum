require('./core');
require('./error-handler-v8');

Script.load = async (name, source) => {
  Script._load(name, source);
  return await import(name);
};
