# Concurso: la contraseña más segura

Actividad presencial para docentes. Cada docente se registra con su nombre y una contraseña **inventada**;
el instructor anota las predicciones de quién creen que ganó, la página evalúa todas las contraseñas y se revela el top 2 y el ganador.
Proyecto independiente: no necesita base de datos (todo vive en memoria).

## Páginas

- `/` para los docentes (registro, espera y resultados desde su celular o computadora).
- `/admin` para el instructor (clave: la variable `INSTRUCTOR_KEY`).

## Fases (las avanza el instructor con un botón)

1. **Registro:** los docentes envían su nombre y su contraseña inventada. Ven "en espera de la evaluación".
2. **Predicciones:** el instructor pregunta a cada docente quién cree que ganó (y por qué) y lo anota en el cuaderno del panel.
3. **Resultados:** solo el instructor ve la clasificación completa.
4. **Top 2:** todos ven los dos finalistas y su propio resultado.
5. **Ganador:** se revela al ganador y al segundo lugar. Se muestra la contraseña solo si la persona aceptó; si no, se muestran sus características.

Al evaluar se resume cuántos acertaron al ganador y cuántos al top 2.

## Cómo se evalúa

Se usa la librería zxcvbn (penaliza repeticiones, palabras comunes y patrones) y las contraseñas que están en una lista de claves y patrones comunes quedan eliminadas.
El tiempo "tardaría en caer" supone un ataque muy rápido (10 mil millones de intentos por segundo contra un hash rápido). Es una estimación para comparar, no una medida exacta.

## Privacidad

- Se pide usar una contraseña inventada, no una real.
- La contraseña en texto solo se guarda en memoria si la persona marcó que acepta mostrarla si queda en el top 2.
- **Reiniciar concurso** borra todo. Si el servidor se reinicia, también se borra.

## Variables de entorno (.env)

Copia `.env.example` como `.env`. Para probar en tu computadora: `npm install` y `npm run dev` (Node 20.6 o más), y abre `http://localhost:3000` y `http://localhost:3000/admin`.

| Variable | Para qué sirve | Valor por defecto |
|---|---|---|
| `INSTRUCTOR_KEY` | Clave para entrar a `/admin` | `instructor` |
| `PORT` | Puerto local | `3000` (en Render lo pone Render) |

El `.env` no se sube a GitHub (está en `.gitignore`). En Render, agrega `INSTRUCTOR_KEY` en la pestaña **Environment**.

## Desplegar en Render

1. Sube esta carpeta a un repositorio de GitHub nuevo.
2. En Render: **New > Web Service**, conecta el repo.
3. Build command: `npm install`. Start command: `npm start`. Instance type: Free.
4. En **Environment** agrega `INSTRUCTOR_KEY` con tu clave.
5. Cuando diga Live, comparte la URL con los docentes y entra tú a `/admin`.

Notas:
- El plan gratis se duerme tras 15 min sin tráfico. Abre la página 10 minutos antes de la actividad.
- No hagas un nuevo deploy durante el concurso: un reinicio borra todo.
# concurso_de-_contrase-as
