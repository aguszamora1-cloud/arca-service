const { Arca } = require("@ramiidv/arca-facturacion");

const cache = new Map();

function getArcaInstance({ cuit, cert, key, production }) {
  const cacheKey = `${cuit}-${production ? "prod" : "homo"}`;
  
  if (!cache.has(cacheKey)) {
    const instance = new Arca({
      cuit: Number(cuit),
      cert,
      key,
      production: production === true || production === "true",
    });
    cache.set(cacheKey, instance);
  }
  
  return cache.get(cacheKey);
}

module.exports = { getArcaInstance };
