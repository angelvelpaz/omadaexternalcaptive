'use strict';

const swaggerJsdoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');

const options = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'Portal Cautivo API',
      version: '1.0.0',
      description: 'API del portal cautivo multi-vendor (MikroTik, UniFi, Omada)',
    },
    servers: [
      {
        url: '/',
        description: 'Servidor local',
      },
    ],
  },
  apis: ['./src/routes/*.js', './src/app.js'],
};

const specs = swaggerJsdoc(options);

function setupSwagger(app) {
  const swaggerUiOptions = {
    explorer: true,
    customCss: '.swagger-ui .topbar { display: none }',
  };

  // En producción, proteger con ADMIN_SECRET
  if (process.env.NODE_ENV === 'production') {
    app.use('/docs', (req, res, next) => {
      const token = req.query.token || req.headers['x-admin-token'];
      if (token === process.env.ADMIN_SECRET) {
        return next();
      }
      return res.status(403).json({ error: 'Se requiere token de administrador para acceder a la documentación.' });
    });
  }

  app.use('/docs', swaggerUi.serve, swaggerUi.setup(specs, swaggerUiOptions));
  app.get('/openapi.json', (req, res) => {
    res.setHeader('Content-Type', 'application/json');
    res.send(specs);
  });
}

module.exports = { setupSwagger };
