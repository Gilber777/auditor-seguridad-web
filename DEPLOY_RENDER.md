# Guía de Conexión y Despliegue en Render

Este proyecto está configurado mediante un **Render Blueprint** ([`render.yaml`](./render.yaml)) que despliega coordinadamente:
1. **Backend API en FastAPI** (`auditor-seguridad-api` en Python 3.12)
2. **Frontend en Next.js** (`auditor-seguridad-web` en Node.js 20)

---

## Paso 1: Subir el proyecto a GitHub o GitLab

Si aún no tienes el repositorio remoto configurado, crea uno en [GitHub](https://github.com/new) y ejecuta en tu terminal:

```bash
# Agregar origen remoto (reemplaza con tu URL de repositorio)
git remote add origin https://github.com/TU_USUARIO/auditor-seguridad-web.git

# Asegurar rama main y subir cambios
git branch -M main
git push -u origin main
```

---

## Paso 2: Conectar el repositorio en Render

1. Inicia sesión en [Render Dashboard](https://dashboard.render.com).
2. Haz clic en el botón superior **"New +"** y selecciona **"Blueprint"**.
3. Conecta tu cuenta de GitHub/GitLab y selecciona el repositorio de tu proyecto.
4. Render leerá automáticamente el archivo [`render.yaml`](./render.yaml) en la raíz y detectará ambos servicios:
   - **`auditor-seguridad-api`** (Web Service · Python · `uvicorn main:app --host 0.0.0.0 --port $PORT`)
   - **`auditor-seguridad-web`** (Web Service · Node · `npm run start -- -p $PORT`)
5. Haz clic en **"Apply"** o **"Create Services"**.

---

## Paso 3: Verificación y Enlaces Generados

Render asignará automáticamente dominios HTTPS gratuitos a cada servicio:
- **API Backend:** `https://auditor-seguridad-api.onrender.com` (Documentación en `/docs`)
- **Frontend Web App:** `https://auditor-seguridad-web.onrender.com`

Ambos servicios cuentan con recarga automática (*Auto-Deploy*) cada vez que hagas un `git push` a la rama `main`.
