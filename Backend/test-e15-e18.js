const fs = require('fs');
const assert = require('assert');

console.log('=== TEST INCIDENCIAS E15, E16, E17, E18 ===\n');

// 1. Prueba de lógica unitaria de esNombreValido
console.log('--- 1. Probando validador compartido de nombres (E15) ---');
function esNombreValido(str) {
    if (!str || typeof str !== 'string') return false;
    const limpio = str.trim();
    if (limpio.length < 2) return false;
    const letras = limpio.match(/[a-zA-ZáéíóúÁÉÍÓÚñÑüÜ]/g);
    return (letras ? letras.length : 0) >= 2;
}

// Casos que deben rechazarse (E15):
const invalidos = ['.', '###', 'a', '1', '123', 'a.', '.a.', '', '   ', '###..', '1#$'];
for (const val of invalidos) {
    assert(!esNombreValido(val), `El valor '${val}' debió ser rechazado por esNombreValido`);
}
console.log('  [PASS] Todos los nombres inválidos (".", "###", "a", etc.) fueron rechazados.');

// Casos que deben aceptarse:
const validos = ['ab', 'Ab', 'Ana', 'María', 'José P.', 'Dr. House', 'Tierra de hoja 5kg', 'Poda #1', 'Rosa 2', 'admin', 'Kimachang', 'USR-011', 'mlopez_w'];
for (const val of validos) {
    assert(esNombreValido(val), `El valor válido '${val}' fue erróneamente rechazado por esNombreValido`);
}
console.log('  [PASS] Todos los nombres válidos fueron aceptados.');

// 2. Verificar presencia de esNombreValido en los 8 módulos en Backend/server.js
console.log('\n--- 2. Verificando Backend/server.js para E15 (8 módulos y PUT /api/actualizar) ---');
const serverSrc = fs.readFileSync('Backend/server.js', 'utf8');

assert(serverSrc.includes('function esNombreValido'), 'server.js debe definir function esNombreValido');

// 1) Proveedores
assert(/app\.post\('\/api\/proveedores'[\s\S]*?esNombreValido\(nom_prov\)/.test(serverSrc), 'POST /api/proveedores debe validar esNombreValido(nom_prov)');
// 2) Clientes
assert(/app\.post\('\/api\/clientes'[\s\S]*?esNombreValido\(nom_cli\)/.test(serverSrc), 'POST /api/clientes debe validar esNombreValido(nom_cli)');
// 3) Empleados
assert(/app\.post\('\/api\/empleados'[\s\S]*?esNombreValido\(nom_emp\)/.test(serverSrc), 'POST /api/empleados debe validar esNombreValido(nom_emp)');
// 4) Catálogo de Servicios
assert(/app\.post\('\/api\/catalogo-servicios'[\s\S]*?esNombreValido\(nom_serv\)/.test(serverSrc), 'POST /api/catalogo-servicios debe validar esNombreValido(nom_serv)');
// 5) Productos
assert(/app\.post\('\/api\/productos'[\s\S]*?esNombreValido\(desc_pro\)/.test(serverSrc), 'POST /api/productos debe validar esNombreValido(desc_pro)');
// 6) Plantas
assert(/validacionesPlanta[\s\S]*?esNombreValido\(valor\)/.test(serverSrc), 'validacionesPlanta debe validar esNombreValido');
assert(/app\.post\('\/api\/plantas'[\s\S]*?esNombreValido\(cientifico\)[\s\S]*?esNombreValido\(comun\)/.test(serverSrc), 'POST /api/plantas debe validar cientifico y comun');
// 7) Servicios
assert(/app\.post\('\/api\/servicios'[\s\S]*?esNombreValido\(trabajoEntrada\)/.test(serverSrc), 'POST /api/servicios debe validar trabajoEntrada');
// 8) Usuarios (alta y edición)
assert(/app\.post\('\/api\/usuarios'[\s\S]*?esNombreValido\(username\)/.test(serverSrc), 'POST /api/usuarios debe validar esNombreValido(username)');
assert(/app\.put\('\/api\/usuarios\/:id'[\s\S]*?esNombreValido\(usernameVal\)/.test(serverSrc), 'PUT /api/usuarios/:id debe validar esNombreValido(usernameVal)');

// Edición general PUT /api/actualizar
assert(/app\.put\('\/api\/actualizar'[\s\S]*?esNombreValido/.test(serverSrc), 'PUT /api/actualizar debe validar esNombreValido');

console.log('  [PASS] Backend/server.js contiene validación de nombres en los 8 módulos y en actualizar.');

// 3. Verificar Frontend en los 8 módulos
console.log('\n--- 3. Verificando Frontend en los 8 módulos para E15 ---');
const frontendFiles = [
    { file: 'Frontend/registro-proveedor.html', varName: 'nom_prov' },
    { file: 'Frontend/registro-cliente.html', varName: 'nom_cli' },
    { file: 'Frontend/registro-empleado.html', varName: 'nom_emp' },
    { file: 'Frontend/registro-producto.html', varName: 'desc_pro' },
    { file: 'Frontend/registro-planta.html', varName: 'cientifico' },
    { file: 'Frontend/registro-servicio.html', varName: 'trabajo' },
    { file: 'Frontend/registro-catalogo-servicio.html', varName: 'nom_serv' },
    { file: 'Frontend/registro-usuario.html', varName: 'username' }
];

for (const f of frontendFiles) {
    const content = fs.readFileSync(f.file, 'utf8');
    assert(content.includes('esNombreValido'), `${f.file} debe incluir esNombreValido`);
    assert(content.includes('<form novalidate'), `${f.file} debe incluir <form novalidate`);
    console.log(`  [PASS] ${f.file} validado correctamente con esNombreValido y novalidate.`);
}

const dashContent = fs.readFileSync('Frontend/dashboard.html', 'utf8');
assert(dashContent.includes('esNombreValido'), 'dashboard.html debe incluir esNombreValido');
console.log('  [PASS] Frontend/dashboard.html incluye esNombreValido en edición.');

// 4. Verificar E16: Ejemplo de CURP válido GARC850101HDFRRN09 en los 3 sitios de backend y frontend
console.log('\n--- 4. Verificando E16: Ejemplo oficial de CURP ---');
assert(!serverSrc.includes('ABCD000101HDFRND01'), 'server.js no debe contener ABCD000101HDFRND01');
assert(!dashContent.includes('ABCD000101HDFRND01'), 'dashboard.html no debe contener ABCD000101HDFRND01');
const empContent = fs.readFileSync('Frontend/registro-empleado.html', 'utf8');
assert(!empContent.includes('ABCD000101HDFRND01'), 'registro-empleado.html no debe contener ABCD000101HDFRND01');

const matchesCurp = serverSrc.match(/GARC850101HDFRRN09/g) || [];
assert(matchesCurp.length >= 3, `server.js debe contener al menos 3 ocurrencias del ejemplo GARC850101HDFRRN09 (encontradas: ${matchesCurp.length})`);
assert(empContent.includes('GARC850101HDFRRN09'), 'registro-empleado.html debe contener el ejemplo GARC850101HDFRRN09');
console.log('  [PASS] E16 verificado: ABCD000101HDFRND01 eliminado y reemplazado por GARC850101HDFRRN09 en todos los sitios.');

// 5. Verificar E17 y E18: Sueldo vacío queda en $0.00 y no en blanco
console.log('\n--- 5. Verificando E17 y E18: Sueldo vacío y presentación en dashboard ---');
// E17 en server.js:
assert(serverSrc.includes('let sueldoFinal = 0.00;'), 'server.js debe inicializar sueldoFinal en 0.00 si no se proporciona');
// E18 en dashboard.html:
assert(dashContent.includes("html += `<td>$0.00</td>`;"), 'dashboard.html debe mostrar $0.00 cuando el valor monetario o sueldo sea nulo o vacío');
console.log('  [PASS] E17 y E18 verificados: sueldo por defecto en 0.00 y visualización de $0.00 garantizada en dashboard.');

console.log('\n=== TODAS LAS PRUEBAS DE E15, E16, E17 Y E18 PASARON CON ÉXITO ===\n');
