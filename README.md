# Buscador de Producto Informático y sus vulnerabilidades reconocidas

Este script en PHP permite buscar información sobre productos informáticos y obtener sus vulnerabilidades conocidas. Utiliza múltiples fuentes y técnicas de scraping para recopilar y presentar la información de manera detallada.

## Versiones

- **Versión:** 0.1.5 Alpha
- **Autor:** AJ Melian
- **Fecha:** 2024-06-05

## Uso

1. Asegúrate de tener instalado PHP y cURL en tu sistema.
2. Clona el repositorio o descarga el archivo PHP.
3. Ejecuta el script proporcionando los nombres de los productos como argumentos.

Ejemplo de uso:
```bash
php buscar_vulnerabilidades.php "Producto1 1.0"
```

## Funcionalidades

- **fetchUrl:** Función para obtener el contenido de una URL utilizando cURL.
- **processProduct:** Función principal que procesa un producto y obtiene sus vulnerabilidades.
- **runProcesses:** Ejecuta los procesos de manera paralela o secuencial, dependiendo del soporte de la máquina.

## Dependencias

- **PHP:** El script está escrito en PHP.
- **cURL:** Se utiliza cURL para realizar las solicitudes HTTP.

## Contribuciones

Las contribuciones son bienvenidas. Si deseas contribuir al proyecto, por favor sigue estos pasos:

1. Haz un fork del repositorio.
2. Crea una nueva rama para tu funcionalidad (`git checkout -b feature/nueva-funcionalidad`).
3. Haz tus cambios y realiza los commits (`git commit -am 'Agrega una nueva funcionalidad'`).
4. Haz push a la rama (`git push origin feature/nueva-funcionalidad`).
5. Crea un pull request.

## Licencia

Este proyecto está bajo la Licencia [MIT](LICENSE).
