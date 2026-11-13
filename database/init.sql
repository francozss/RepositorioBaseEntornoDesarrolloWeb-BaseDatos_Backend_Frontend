-- =============================================================================
-- ARCHIVO: script.sql
-- PROYECTO: Plataforma Integral E-commerce B2C/B2B & ERP de Gestión
-- VERSIÓN: 3.0 — Migración Integral Ejecutable (36 Tablas Normalizadas + Datos)
-- MOTOR DE BASE DE DATOS: PostgreSQL 14+
-- CUMPLIMIENTO NORMATIVO: 1FN, 2FN, 3FN, Trazabilidad Dual y Borrado Lógico
-- =============================================================================
-- CREDENCIALES DE PRUEBA (CONTRASEÑAS EN TEXTO PLANO DOCUMENTADAS):
-- 1. Super Administrador : admin@sportcorp.pe        | Pass: AdminSport#2026!
-- 2. Gerente Comercial   : comercial@sportcorp.pe    | Pass: VentasPro#2026!
-- 3. Almacenero          : almacen@sportcorp.pe      | Pass: KardexSafe#2026!
-- 4. Vendedor POS        : pos.lima@sportcorp.pe     | Pass: CajaTienda#2026!
-- 5. Cliente Mayorista   : compras@clubatletico.pe   | Pass: MayoristaB2B#2026!
-- 6. Cliente Minorista   : valeria.mendoza@gmail.com | Pass: ClienteB2C#2026!
-- =============================================================================

BEGIN;

-- =============================================================================
-- SECCIÓN 0: EXTENSIONES Y CONFIGURACIÓN INICIAL
-- =============================================================================

-- Habilita funciones criptográficas nativas (crypt y gen_salt) para generar hashes Bcrypt reales
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- =============================================================================
-- MÓDULO 1: USUARIOS, ROLES Y SEGURIDAD GRANULAR (RBAC)
-- =============================================================================

-- Almacena los perfiles o roles funcionales que determinan el nivel de acceso en la plataforma
CREATE TABLE roles (
    id SERIAL PRIMARY KEY, -- Identificador único autoincremental del rol
    name VARCHAR(50) NOT NULL, -- Nombre único del rol operativo o comercial (ej. Super Administrador)
    description TEXT, -- Descripción detallada de las responsabilidades y alcance del rol
    is_system_role BOOLEAN DEFAULT FALSE NOT NULL, -- Indica si es un rol protegido del sistema (TRUE) o editable (FALSE)
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL, -- Fecha y hora exacta de creación del registro
    created_by INT NOT NULL, -- Identificador del usuario que creó el registro
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL, -- Fecha y hora de la última actualización del registro
    updated_by INT, -- Identificador del usuario que realizó la última modificación
    deleted_at TIMESTAMP, -- Fecha y hora de borrado lógico (NULL indica registro activo)
    deleted_by INT, -- Identificador del usuario que ejecutó el borrado lógico
    CONSTRAINT uq_roles_name UNIQUE (name) -- Garantiza que no existan nombres de roles duplicados
);

-- Almacena el catálogo maestro de permisos granulares por código y módulo funcional
CREATE TABLE permissions (
    id SERIAL PRIMARY KEY, -- Identificador único autoincremental del permiso
    code VARCHAR(80) NOT NULL, -- Código técnico único del permiso (ej. products.create, kardex.read)
    module VARCHAR(50) NOT NULL, -- Módulo funcional al que pertenece el permiso (ej. products, orders, branding)
    description TEXT, -- Explicación clara de la acción que autoriza este permiso
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL, -- Fecha y hora de creación del permiso
    created_by INT NOT NULL, -- Identificador del usuario creador del registro
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL, -- Fecha y hora de última modificación
    updated_by INT, -- Identificador del usuario que actualizó el permiso
    deleted_at TIMESTAMP, -- Marca de tiempo de borrado lógico (NULL = activo)
    deleted_by INT, -- Identificador del usuario que eliminó lógicamente el registro
    CONSTRAINT uq_permissions_code UNIQUE (code) -- Evita códigos de permisos duplicados en el sistema
);

-- Tabla asociativa que resuelve la relación muchos a muchos (M:N) entre roles y permisos
CREATE TABLE role_permissions (
    id SERIAL PRIMARY KEY, -- Identificador único de la asignación rol-permiso
    role_id INT NOT NULL, -- Clave foránea que referencia al rol que recibe el permiso
    permission_id INT NOT NULL, -- Clave foránea que referencia al permiso otorgado
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL, -- Fecha y hora en que se otorgó el permiso
    created_by INT NOT NULL, -- Identificador del usuario que asignó el permiso
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL, -- Fecha y hora de última actualización
    updated_by INT, -- Identificador del usuario que modificó la asignación
    deleted_at TIMESTAMP, -- Marca de tiempo de revocación lógica (NULL = permiso vigente)
    deleted_by INT, -- Identificador del usuario que revocó lógicamente el permiso
    CONSTRAINT fk_role_permissions_role FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE, -- Integridad referencial con roles
    CONSTRAINT fk_role_permissions_permission FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE, -- Integridad referencial con permisos
    CONSTRAINT uq_role_permissions_pair UNIQUE (role_id, permission_id) -- Impide asignar el mismo permiso dos veces al mismo rol
);

-- Almacena las cuentas de usuario del personal interno (ERP) y clientes (B2C y B2B)
CREATE TABLE users (
    id SERIAL PRIMARY KEY, -- Identificador único autoincremental del usuario
    role_id INT NOT NULL, -- Clave foránea hacia roles que define los permisos de acceso del usuario
    first_name VARCHAR(100) NOT NULL, -- Nombres propios del usuario o representante legal
    last_name VARCHAR(100) NOT NULL, -- Apellidos del usuario
    email VARCHAR(150) NOT NULL, -- Correo electrónico único utilizado como credencial de inicio de sesión
    document_type VARCHAR(20) NOT NULL, -- Tipo de documento de identidad (DNI, RUC, CE, PASAPORTE)
    document_number VARCHAR(20) NOT NULL, -- Número de documento fiscal o identidad válido en Perú
    phone VARCHAR(30), -- Teléfono móvil o fijo de contacto del usuario
    password_hash VARCHAR(255) NOT NULL, -- Hash criptográfico Bcrypt de la contraseña del usuario
    is_active BOOLEAN DEFAULT TRUE NOT NULL, -- Indicador de cuenta habilitada (TRUE) o suspendida (FALSE)
    last_login_at TIMESTAMP, -- Fecha y hora del último inicio de sesión exitoso
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL, -- Fecha y hora de registro de la cuenta
    created_by INT NOT NULL, -- Identificador del usuario que creó la cuenta
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL, -- Fecha y hora de última edición del perfil
    updated_by INT, -- Identificador del usuario que actualizó el perfil
    deleted_at TIMESTAMP, -- Marca de tiempo de baja lógica (NULL = cuenta activa)
    deleted_by INT, -- Identificador del usuario que dio de baja la cuenta
    CONSTRAINT fk_users_role FOREIGN KEY (role_id) REFERENCES roles(id), -- Vincula cada usuario con un rol válido
    CONSTRAINT uq_users_email UNIQUE (email), -- Garantiza correos electrónicos únicos por cuenta
    CONSTRAINT uq_users_document UNIQUE (document_type, document_number) -- Evita duplicidad de documentos de identidad
);

-- =============================================================================
-- MÓDULO 2: CATÁLOGO DE PRODUCTOS, MARCAS Y VARIANTES (1FN, 2FN, 3FN)
-- =============================================================================

-- Almacena el catálogo maestro de marcas comerciales comercializadas por la empresa
CREATE TABLE brands (
    id SERIAL PRIMARY KEY, -- Identificador único autoincremental de la marca
    name VARCHAR(100) NOT NULL, -- Nombre comercial oficial de la marca (ej. Nike, Adidas)
    slug VARCHAR(100) NOT NULL, -- Identificador amigable en minúsculas para URLs y filtros web
    description TEXT, -- Reseña descriptiva de la marca comercial
    logo_url VARCHAR(255), -- Ruta o URL al logotipo oficial de la marca
    is_active BOOLEAN DEFAULT TRUE NOT NULL, -- Indica si la marca está visible en el catálogo
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL, -- Fecha y hora de creación de la marca
    created_by INT NOT NULL, -- Identificador del usuario que registró la marca
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL, -- Fecha y hora de última actualización
    updated_by INT, -- Identificador del usuario que editó la marca
    deleted_at TIMESTAMP, -- Fecha y hora de borrado lógico (NULL = activa)
    deleted_by INT, -- Identificador del usuario que ejecutó el borrado lógico
    CONSTRAINT uq_brands_name UNIQUE (name), -- Evita marcas con nombres repetidos
    CONSTRAINT uq_brands_slug UNIQUE (slug) -- Evita rutas amigables duplicadas
);

-- Almacena la estructura jerárquica recursiva de categorías y subcategorías de productos
CREATE TABLE categories (
    id SERIAL PRIMARY KEY, -- Identificador único autoincremental de la categoría
    parent_id INT, -- Clave foránea auto-referenciada a la categoría padre (NULL = categoría raíz)
    name VARCHAR(100) NOT NULL, -- Nombre comercial de la categoría (ej. Calzado, Running)
    slug VARCHAR(100) NOT NULL, -- Identificador amigable para navegación y filtros SEO
    description TEXT, -- Descripción del tipo de productos agrupados en la categoría
    is_active BOOLEAN DEFAULT TRUE NOT NULL, -- Controla si la categoría se muestra en la tienda
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL, -- Fecha y hora de creación
    created_by INT NOT NULL, -- Identificador del usuario creador
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL, -- Fecha y hora de última modificación
    updated_by INT, -- Identificador del usuario modificador
    deleted_at TIMESTAMP, -- Marca de tiempo de borrado lógico (NULL = activa)
    deleted_by INT, -- Identificador del usuario que eliminó lógicamente la categoría
    CONSTRAINT fk_categories_parent FOREIGN KEY (parent_id) REFERENCES categories(id), -- Soporta jerarquía multinivel
    CONSTRAINT uq_categories_slug UNIQUE (slug) -- Garantiza rutas URL únicas por categoría
);

-- Catálogo maestro normalizado para los segmentos demográficos aprobados (adultos, ninos, sin_clasificacion)
CREATE TABLE demographic_segments (
    id SERIAL PRIMARY KEY, -- Identificador único del segmento demográfico
    name VARCHAR(50) NOT NULL, -- Nombre estandarizado del segmento (adultos, ninos, sin_clasificacion)
    description TEXT, -- Explicación del público objetivo de este segmento
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL, -- Fecha y hora de creación
    created_by INT NOT NULL, -- Identificador del usuario creador
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL, -- Fecha y hora de última modificación
    updated_by INT, -- Identificador del usuario modificador
    deleted_at TIMESTAMP, -- Marca de tiempo de borrado lógico (NULL = activo)
    deleted_by INT, -- Identificador del usuario que ejecutó el borrado lógico
    CONSTRAINT uq_demographic_segments_name UNIQUE (name) -- Evita segmentos demográficos duplicados
);

-- Catálogo maestro normalizado para los géneros objetivo aprobados (hombre, mujer, unisex, n_a)
CREATE TABLE target_genders (
    id SERIAL PRIMARY KEY, -- Identificador único del género objetivo
    name VARCHAR(50) NOT NULL, -- Nombre estandarizado del género (hombre, mujer, unisex, n_a)
    description TEXT, -- Descripción operativa de la clasificación por género
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL, -- Fecha y hora de creación
    created_by INT NOT NULL, -- Identificador del usuario creador
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL, -- Fecha y hora de última modificación
    updated_by INT, -- Identificador del usuario modificador
    deleted_at TIMESTAMP, -- Marca de tiempo de borrado lógico (NULL = activo)
    deleted_by INT, -- Identificador del usuario que ejecutó el borrado lógico
    CONSTRAINT uq_target_genders_name UNIQUE (name) -- Garantiza nombres de género únicos
);

-- Catálogo maestro normalizado de colores disponibles para las variantes de productos
CREATE TABLE colors (
    id SERIAL PRIMARY KEY, -- Identificador único autoincremental del color
    name VARCHAR(50) NOT NULL, -- Nombre descriptivo del color (ej. Negro Ébano, Rojo Carmesí)
    hex_code VARCHAR(7) NOT NULL, -- Código hexadecimal estándar de 7 caracteres (ej. #111111)
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL, -- Fecha y hora de creación
    created_by INT NOT NULL, -- Identificador del usuario creador
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL, -- Fecha y hora de última actualización
    updated_by INT, -- Identificador del usuario modificador
    deleted_at TIMESTAMP, -- Marca de tiempo de borrado lógico (NULL = activo)
    deleted_by INT, -- Identificador del usuario que eliminó lógicamente el color
    CONSTRAINT uq_colors_name UNIQUE (name) -- Evita colores duplicados con el mismo nombre
);

-- Catálogo maestro normalizado de materiales de confección o fabricación de artículos
CREATE TABLE materials (
    id SERIAL PRIMARY KEY, -- Identificador único autoincremental del material
    name VARCHAR(100) NOT NULL, -- Nombre técnico o comercial del material (ej. Malla Transpirable)
    description TEXT, -- Características físicas o composición del material
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL, -- Fecha y hora de creación
    created_by INT NOT NULL, -- Identificador del usuario creador
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL, -- Fecha y hora de última actualización
    updated_by INT, -- Identificador del usuario modificador
    deleted_at TIMESTAMP, -- Marca de tiempo de borrado lógico (NULL = activo)
    deleted_by INT, -- Identificador del usuario que ejecutó el borrado lógico
    CONSTRAINT uq_materials_name UNIQUE (name) -- Garantiza materiales únicos en el maestro
);

-- Catálogo maestro normalizado de esquemas y valores de talles (alfabético, numérico niños, calzado, talla única)
CREATE TABLE sizes (
    id SERIAL PRIMARY KEY, -- Identificador único autoincremental de la talla
    size_type VARCHAR(50) NOT NULL, -- Esquema de tallaje (alfabetico, numerico_ninos, calzado, talla_unica)
    size_value VARCHAR(20) NOT NULL, -- Valor específico de la talla (ej. S, M, L, 10, 41, Única)
    sort_order INT DEFAULT 0 NOT NULL, -- Orden numérico para mostrar las tallas ordenadas en la interfaz
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL, -- Fecha y hora de creación
    created_by INT NOT NULL, -- Identificador del usuario creador
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL, -- Fecha y hora de última actualización
    updated_by INT, -- Identificador del usuario modificador
    deleted_at TIMESTAMP, -- Marca de tiempo de borrado lógico (NULL = activo)
    deleted_by INT, -- Identificador del usuario que ejecutó el borrado lógico
    CONSTRAINT uq_sizes_type_value UNIQUE (size_type, size_value) -- Impide duplicar la misma talla dentro de un esquema
);

-- Entidad principal del catálogo comercial que define cada producto general
CREATE TABLE products (
    id SERIAL PRIMARY KEY, -- Identificador único autoincremental del producto
    brand_id INT NOT NULL, -- Clave foránea hacia brands que identifica la marca del producto
    category_id INT NOT NULL, -- Clave foránea hacia categories que clasifica el producto
    demographic_segment_id INT NOT NULL, -- Clave foránea hacia demographic_segments (adultos, ninos, sin_clasificacion)
    target_gender_id INT NOT NULL, -- Clave foránea hacia target_genders (hombre, mujer, unisex, n_a)
    name VARCHAR(150) NOT NULL, -- Nombre comercial completo del producto
    slug VARCHAR(150) NOT NULL, -- Ruta amigable SEO para la ficha pública del producto
    description TEXT, -- Descripción detallada, beneficios y especificaciones técnicas
    is_published BOOLEAN DEFAULT TRUE NOT NULL, -- Indica si el producto está publicado en la tienda pública
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL, -- Fecha y hora de creación del producto
    created_by INT NOT NULL, -- Identificador del usuario que creó el producto
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL, -- Fecha y hora de última edición
    updated_by INT, -- Identificador del usuario que modificó el producto
    deleted_at TIMESTAMP, -- Marca de tiempo de borrado lógico (NULL = activo)
    deleted_by INT, -- Identificador del usuario que eliminó lógicamente el producto
    CONSTRAINT fk_products_brand FOREIGN KEY (brand_id) REFERENCES brands(id), -- Relación con marcas
    CONSTRAINT fk_products_category FOREIGN KEY (category_id) REFERENCES categories(id), -- Relación con categorías
    CONSTRAINT fk_products_segment FOREIGN KEY (demographic_segment_id) REFERENCES demographic_segments(id), -- Relación con segmentos
    CONSTRAINT fk_products_gender FOREIGN KEY (target_gender_id) REFERENCES target_genders(id), -- Relación con géneros
    CONSTRAINT uq_products_slug UNIQUE (slug) -- Garantiza URLs únicas por producto
);

-- Almacena cada combinación física inventariable (SKU único) resultante de color, material y talla
CREATE TABLE product_variants (
    id SERIAL PRIMARY KEY, -- Identificador único autoincremental de la variante física
    product_id INT NOT NULL, -- Clave foránea hacia el producto padre al que pertenece esta variante
    color_id INT NOT NULL, -- Clave foránea hacia colors que define el color de esta variante
    material_id INT NOT NULL, -- Clave foránea hacia materials que define el material principal
    size_id INT NOT NULL, -- Clave foránea hacia sizes que define la talla específica
    sku VARCHAR(100) NOT NULL, -- Código SKU único e irrepetible para control de inventario y Kardex
    base_price DECIMAL(12, 2) NOT NULL, -- Precio unitario base minorista en Soles (PEN)
    stock_current INT DEFAULT 0 NOT NULL, -- Saldo físico actual disponible en almacén
    is_active BOOLEAN DEFAULT TRUE NOT NULL, -- Indica si la variante está habilitada para la venta
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL, -- Fecha y hora de creación de la variante
    created_by INT NOT NULL, -- Identificador del usuario creador
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL, -- Fecha y hora de última actualización
    updated_by INT, -- Identificador del usuario modificador
    deleted_at TIMESTAMP, -- Marca de tiempo de borrado lógico (NULL = activa)
    deleted_by INT, -- Identificador del usuario que dio de baja la variante
    CONSTRAINT fk_variants_product FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE, -- Relación con producto
    CONSTRAINT fk_variants_color FOREIGN KEY (color_id) REFERENCES colors(id), -- Relación con color
    CONSTRAINT fk_variants_material FOREIGN KEY (material_id) REFERENCES materials(id), -- Relación con material
    CONSTRAINT fk_variants_size FOREIGN KEY (size_id) REFERENCES sizes(id), -- Relación con talla
    CONSTRAINT uq_variants_sku UNIQUE (sku), -- Garantiza unicidad estricta del código SKU
    CONSTRAINT uq_variants_combination UNIQUE (product_id, color_id, material_id, size_id), -- Evita variantes duplicadas con mismos atributos
    CONSTRAINT chk_variants_price_positive CHECK (base_price >= 0), -- Impide precios negativos
    CONSTRAINT chk_variants_stock_non_negative CHECK (stock_current >= 0) -- Impide existencias negativas
);

-- Almacena las fotografías de galería asociadas a productos generales o variantes específicas
CREATE TABLE product_images (
    id SERIAL PRIMARY KEY, -- Identificador único autoincremental de la imagen
    product_id INT NOT NULL, -- Clave foránea hacia el producto al que pertenece la fotografía
    product_variant_id INT, -- Clave foránea opcional si la imagen corresponde a un color/variante específica
    image_url VARCHAR(255) NOT NULL, -- URL pública o ruta de almacenamiento de la fotografía
    alt_text VARCHAR(150), -- Texto alternativo descriptivo para accesibilidad y posicionamiento SEO
    is_primary BOOLEAN DEFAULT FALSE NOT NULL, -- Indica si es la imagen principal de portada del producto
    sort_order INT DEFAULT 0 NOT NULL, -- Orden de visualización en el carrusel de galería
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL, -- Fecha y hora de carga de la imagen
    created_by INT NOT NULL, -- Identificador del usuario que subió la imagen
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL, -- Fecha y hora de última edición
    updated_by INT, -- Identificador del usuario modificador
    deleted_at TIMESTAMP, -- Marca de tiempo de borrado lógico (NULL = vigente)
    deleted_by INT, -- Identificador del usuario que eliminó lógicamente la imagen
    CONSTRAINT fk_product_images_product FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE, -- Relación con producto
    CONSTRAINT fk_product_images_variant FOREIGN KEY (product_variant_id) REFERENCES product_variants(id) ON DELETE SET NULL -- Relación opcional con variante
);

-- =============================================================================
-- MÓDULO 3: PRECIOS ESCALONADOS POR TRAMOS DE CANTIDAD (B2B / B2C)
-- =============================================================================

-- Define los tramos maestros de volumen aprobados (Minorista 1-5, Mayorista 1: 6-11, Mayorista 2: 12-23, Mayorista 3: 24+)
CREATE TABLE pricing_tiers (
    id SERIAL PRIMARY KEY, -- Identificador único autoincremental del tramo de cantidad
    tier_name VARCHAR(50) NOT NULL, -- Nombre comercial del tramo (ej. Minorista, Mayorista 1)
    min_quantity INT NOT NULL, -- Cantidad mínima de unidades requeridas para activar este tramo
    max_quantity INT, -- Cantidad máxima de unidades del tramo (NULL indica límite abierto "a más")
    description TEXT, -- Explicación de la política comercial aplicable a este tramo
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL, -- Fecha y hora de creación del tramo
    created_by INT NOT NULL, -- Identificador del usuario creador
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL, -- Fecha y hora de última modificación
    updated_by INT, -- Identificador del usuario modificador
    deleted_at TIMESTAMP, -- Marca de tiempo de borrado lógico (NULL = activo)
    deleted_by INT, -- Identificador del usuario que ejecutó el borrado lógico
    CONSTRAINT uq_pricing_tiers_name UNIQUE (tier_name), -- Evita nombres de tramos repetidos
    CONSTRAINT chk_pricing_tiers_min CHECK (min_quantity >= 1), -- La cantidad mínima debe ser al menos 1 unidad
    CONSTRAINT chk_pricing_tiers_range CHECK (max_quantity IS NULL OR max_quantity >= min_quantity) -- Valida coherencia del rango
);

-- Asigna el precio unitario específico de cada variante según el tramo de volumen comprado
CREATE TABLE product_volume_prices (
    id SERIAL PRIMARY KEY, -- Identificador único autoincremental de la tarifa escalonada
    product_variant_id INT NOT NULL, -- Clave foránea hacia la variante física a la que aplica el precio
    pricing_tier_id INT NOT NULL, -- Clave foránea hacia el tramo de cantidad correspondiente
    unit_price DECIMAL(12, 2) NOT NULL, -- Precio unitario con descuento aplicable dentro del tramo
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL, -- Fecha y hora de registro de la tarifa
    created_by INT NOT NULL, -- Identificador del usuario creador
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL, -- Fecha y hora de última actualización
    updated_by INT, -- Identificador del usuario modificador
    deleted_at TIMESTAMP, -- Marca de tiempo de borrado lógico (NULL = vigente)
    deleted_by INT, -- Identificador del usuario que eliminó lógicamente la tarifa
    CONSTRAINT fk_volume_prices_variant FOREIGN KEY (product_variant_id) REFERENCES product_variants(id) ON DELETE CASCADE, -- Relación con variante
    CONSTRAINT fk_volume_prices_tier FOREIGN KEY (pricing_tier_id) REFERENCES pricing_tiers(id), -- Relación con tramo
    CONSTRAINT uq_volume_prices_variant_tier UNIQUE (product_variant_id, pricing_tier_id), -- Un único precio por variante y tramo
    CONSTRAINT chk_volume_prices_positive CHECK (unit_price >= 0) -- Asegura precios unitarios no negativos
);

-- =============================================================================
-- MÓDULO 4: CARGA MASIVA Y CONTROL ASÍNCRONO (BACKGROUND WORKERS)
-- =============================================================================

-- Registra y monitorea los lotes de importación masiva procesados en segundo plano
CREATE TABLE bulk_import_jobs (
    id SERIAL PRIMARY KEY, -- Identificador único autoincremental del trabajo de importación
    user_id INT NOT NULL, -- Clave foránea hacia users que identifica quién subió el archivo
    file_name VARCHAR(255) NOT NULL, -- Nombre original del archivo CSV o Excel cargado
    import_type VARCHAR(50) NOT NULL, -- Tipo de entidad procesada (productos, variantes, precios, marcas)
    status VARCHAR(50) DEFAULT 'pendiente' NOT NULL, -- Estado del worker (pendiente, procesando, exitoso, completado_con_errores, rechazado)
    total_rows INT DEFAULT 0 NOT NULL, -- Número total de filas detectadas en el archivo
    success_rows INT DEFAULT 0 NOT NULL, -- Cantidad de filas validadas e insertadas correctamente
    error_rows INT DEFAULT 0 NOT NULL, -- Cantidad de filas rechazadas por validación Fail-Fast
    started_at TIMESTAMP, -- Marca de tiempo en que el worker inició el procesamiento
    finished_at TIMESTAMP, -- Marca de tiempo en que el worker finalizó el procesamiento
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL, -- Fecha y hora de recepción del archivo
    created_by INT NOT NULL, -- Identificador del usuario que registró la carga
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL, -- Fecha y hora de última actualización de estado
    updated_by INT, -- Identificador del usuario o proceso actualizador
    deleted_at TIMESTAMP, -- Marca de tiempo de borrado lógico (NULL = visible)
    deleted_by INT, -- Identificador del usuario que ocultó lógicamente el historial
    CONSTRAINT fk_bulk_jobs_user FOREIGN KEY (user_id) REFERENCES users(id) -- Relación con el usuario operador
);

-- Almacena el reporte detallado fila por fila de las fallas detectadas en la validación Fail-Fast
CREATE TABLE bulk_import_errors (
    id SERIAL PRIMARY KEY, -- Identificador único autoincremental del registro de error
    bulk_import_job_id INT NOT NULL, -- Clave foránea hacia el lote de importación al que pertenece el error
    row_number INT NOT NULL, -- Número exacto de la fila con error dentro del archivo CSV/Excel
    row_data TEXT NOT NULL, -- Contenido textual original de la fila rechazada para facilitar su corrección
    error_message TEXT NOT NULL, -- Motivo técnico y funcional exacto del rechazo de validación
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL, -- Fecha y hora de detección del error
    created_by INT NOT NULL, -- Identificador del usuario o sistema que registró el error
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL, -- Fecha y hora de última modificación
    updated_by INT, -- Identificador del usuario modificador
    deleted_at TIMESTAMP, -- Marca de tiempo de borrado lógico (NULL = activo)
    deleted_by INT, -- Identificador del usuario que ejecutó el borrado lógico
    CONSTRAINT fk_bulk_errors_job FOREIGN KEY (bulk_import_job_id) REFERENCES bulk_import_jobs(id) ON DELETE CASCADE -- Relación con el lote padre
);

-- =============================================================================
-- MÓDULO 5: CONTROL DE INVENTARIO Y KARDEX COMERCIAL INMUTABLE
-- =============================================================================

-- Bitácora histórica e inmutable de todos los movimientos físicos de inventario por SKU
CREATE TABLE inventory_movements (
    id SERIAL PRIMARY KEY, -- Identificador único e inmutable del asiento de Kardex
    product_variant_id INT NOT NULL, -- Clave foránea hacia la variante física afectada
    movement_type VARCHAR(50) NOT NULL, -- Tipo de operación (entrada_compra, salida_venta, devolucion, ajuste_inventario)
    quantity INT NOT NULL, -- Cantidad de unidades ingresadas o retiradas en la operación
    previous_stock INT NOT NULL, -- Saldo físico de existencias inmediatamente antes del movimiento
    new_stock INT NOT NULL, -- Saldo físico resultante inmediatamente después del movimiento
    reference_document VARCHAR(100), -- Código del documento respaldo (Orden de Compra, Pedido, Acta de Inventario)
    notes TEXT, -- Observaciones operativas o justificación del movimiento
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL, -- Fecha y hora exacta e inalterable del movimiento
    created_by INT NOT NULL, -- Identificador del usuario responsable de ejecutar el movimiento
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL, -- Fecha y hora de registro inicial
    updated_by INT, -- Reservado (permanece NULL por inmutabilidad del Kardex)
    deleted_at TIMESTAMP, -- Reservado (permanece NULL por prohibición de eliminación en Kardex)
    deleted_by INT, -- Reservado (permanece NULL por integridad contable)
    CONSTRAINT fk_kardex_variant FOREIGN KEY (product_variant_id) REFERENCES product_variants(id), -- Relación con variante SKU
    CONSTRAINT chk_kardex_quantity_positive CHECK (quantity > 0), -- La magnitud del movimiento siempre debe ser mayor a cero
    CONSTRAINT chk_kardex_stocks_valid CHECK (previous_stock >= 0 AND new_stock >= 0) -- Los saldos nunca pueden ser negativos
);

-- Configura los umbrales mínimos de stock por variante para disparar alertas automáticas
CREATE TABLE stock_alerts_config (
    id SERIAL PRIMARY KEY, -- Identificador único autoincremental de la regla de alerta
    product_variant_id INT NOT NULL, -- Clave foránea única hacia la variante vigilada (relación 1:1)
    min_threshold INT DEFAULT 5 NOT NULL, -- Cantidad mínima crítica de unidades antes de emitir alerta
    is_active BOOLEAN DEFAULT TRUE NOT NULL, -- Indica si la vigilancia automática de stock está encendida
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL, -- Fecha y hora de creación de la regla
    created_by INT NOT NULL, -- Identificador del usuario que configuró la alerta
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL, -- Fecha y hora de última modificación
    updated_by INT, -- Identificador del usuario modificador
    deleted_at TIMESTAMP, -- Marca de tiempo de borrado lógico (NULL = activa)
    deleted_by INT, -- Identificador del usuario que desactivó lógicamente la alerta
    CONSTRAINT fk_stock_alerts_variant FOREIGN KEY (product_variant_id) REFERENCES product_variants(id) ON DELETE CASCADE, -- Relación con variante
    CONSTRAINT uq_stock_alerts_variant UNIQUE (product_variant_id), -- Garantiza una sola configuración por variante
    CONSTRAINT chk_stock_alerts_min CHECK (min_threshold >= 0) -- El umbral mínimo no puede ser negativo
);

-- =============================================================================
-- MÓDULO 6: GESTIÓN DE VENTAS, PAGOS Y LOGÍSTICA HÍBRIDA
-- =============================================================================

-- Tabla maestra normalizada (3FN) de canales de origen de las ventas
CREATE TABLE order_channels (
    id SERIAL PRIMARY KEY, -- Identificador único autoincremental del canal de venta
    name VARCHAR(50) NOT NULL, -- Código o nombre del canal (web_b2c, web_b2b, pos_presencial)
    description TEXT, -- Descripción operativa del canal comercial
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL, -- Fecha y hora de creación
    created_by INT NOT NULL, -- Identificador del usuario creador
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL, -- Fecha y hora de última actualización
    updated_by INT, -- Identificador del usuario modificador
    deleted_at TIMESTAMP, -- Marca de tiempo de borrado lógico (NULL = activo)
    deleted_by INT, -- Identificador del usuario que ejecutó el borrado lógico
    CONSTRAINT uq_order_channels_name UNIQUE (name) -- Garantiza canales únicos
);

-- Tabla maestra normalizada (3FN) de estados operativos de los pedidos
CREATE TABLE order_statuses (
    id SERIAL PRIMARY KEY, -- Identificador único autoincremental del estado de pedido
    name VARCHAR(50) NOT NULL, -- Nombre estandarizado del estado (pendiente, procesando, completado, cancelado)
    description TEXT, -- Significado operativo de esta etapa dentro del flujo de ventas
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL, -- Fecha y hora de creación
    created_by INT NOT NULL, -- Identificador del usuario creador
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL, -- Fecha y hora de última actualización
    updated_by INT, -- Identificador del usuario modificador
    deleted_at TIMESTAMP, -- Marca de tiempo de borrado lógico (NULL = activo)
    deleted_by INT, -- Identificador del usuario que ejecutó el borrado lógico
    CONSTRAINT uq_order_statuses_name UNIQUE (name) -- Evita estados de pedido duplicados
);

-- Tabla maestra normalizada (3FN) de medios de pago aceptados en la plataforma
CREATE TABLE payment_methods (
    id SERIAL PRIMARY KEY, -- Identificador único autoincremental del método de pago
    name VARCHAR(50) NOT NULL, -- Nombre del medio de pago (tarjeta, transferencia, efectivo_pos, yape_plin)
    description TEXT, -- Detalle operativo o instrucciones para el cliente
    requires_verification BOOLEAN DEFAULT FALSE NOT NULL, -- Indica si requiere validación manual de comprobante (TRUE) o es automático (FALSE)
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL, -- Fecha y hora de creación
    created_by INT NOT NULL, -- Identificador del usuario creador
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL, -- Fecha y hora de última actualización
    updated_by INT, -- Identificador del usuario modificador
    deleted_at TIMESTAMP, -- Marca de tiempo de borrado lógico (NULL = activo)
    deleted_by INT, -- Identificador del usuario que ejecutó el borrado lógico
    CONSTRAINT uq_payment_methods_name UNIQUE (name) -- Garantiza métodos de pago únicos
);

-- Tabla maestra normalizada (3FN) de estados financieros de las transacciones de pago
CREATE TABLE payment_statuses (
    id SERIAL PRIMARY KEY, -- Identificador único autoincremental del estado de pago
    name VARCHAR(50) NOT NULL, -- Estado estandarizado (pendiente, confirmado, rechazado, reembolsado)
    description TEXT, -- Descripción financiera de la situación del cobro
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL, -- Fecha y hora de creación
    created_by INT NOT NULL, -- Identificador del usuario creador
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL, -- Fecha y hora de última actualización
    updated_by INT, -- Identificador del usuario modificador
    deleted_at TIMESTAMP, -- Marca de tiempo de borrado lógico (NULL = activo)
    deleted_by INT, -- Identificador del usuario que ejecutó el borrado lógico
    CONSTRAINT uq_payment_statuses_name UNIQUE (name) -- Evita estados de pago duplicados
);

-- Tabla maestra normalizada (3FN) de modalidades de entrega logística híbrida
CREATE TABLE fulfillment_types (
    id SERIAL PRIMARY KEY, -- Identificador único autoincremental de la modalidad de entrega
    name VARCHAR(50) NOT NULL, -- Nombre de la modalidad (retiro_tienda, envio_domicilio, agencia_transporte)
    description TEXT, -- Condiciones de entrega y cobertura logística
    base_cost DECIMAL(12, 2) DEFAULT 0.00 NOT NULL, -- Tarifa referencial base de envío (0.00 para retiro en tienda)
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL, -- Fecha y hora de creación
    created_by INT NOT NULL, -- Identificador del usuario creador
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL, -- Fecha y hora de última actualización
    updated_by INT, -- Identificador del usuario modificador
    deleted_at TIMESTAMP, -- Marca de tiempo de borrado lógico (NULL = activo)
    deleted_by INT, -- Identificador del usuario que ejecutó el borrado lógico
    CONSTRAINT uq_fulfillment_types_name UNIQUE (name) -- Garantiza modalidades únicas
);

-- Tabla maestra normalizada (3FN) de estados de seguimiento de despachos y envíos
CREATE TABLE shipping_statuses (
    id SERIAL PRIMARY KEY, -- Identificador único autoincremental del estado de envío
    name VARCHAR(50) NOT NULL, -- Estado logístico (preparando, listo_para_retiro, en_camino, entregado)
    description TEXT, -- Descripción de la etapa de preparación o transporte
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL, -- Fecha y hora de creación
    created_by INT NOT NULL, -- Identificador del usuario creador
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL, -- Fecha y hora de última actualización
    updated_by INT, -- Identificador del usuario modificador
    deleted_at TIMESTAMP, -- Marca de tiempo de borrado lógico (NULL = activo)
    deleted_by INT, -- Identificador del usuario que ejecutó el borrado lógico
    CONSTRAINT uq_shipping_statuses_name UNIQUE (name) -- Evita estados logísticos duplicados
);

-- Cabecera transaccional de los pedidos comerciales generados en web B2C, web B2B o POS
CREATE TABLE orders (
    id SERIAL PRIMARY KEY, -- Identificador único autoincremental interno de la orden
    order_number VARCHAR(30) NOT NULL, -- Código comercial legible del pedido (ej. PED-2026-0001)
    user_id INT NOT NULL, -- Clave foránea hacia users que identifica al cliente comprador
    channel_id INT NOT NULL, -- Clave foránea hacia order_channels (web_b2c, web_b2b, pos_presencial)
    status_id INT NOT NULL, -- Clave foránea hacia order_statuses que indica el estado actual del pedido
    subtotal_amount DECIMAL(12, 2) NOT NULL, -- Suma de los subtotales de productos antes de costos de envío
    shipping_amount DECIMAL(12, 2) DEFAULT 0.00 NOT NULL, -- Costo total de logística aplicado al pedido
    total_amount DECIMAL(12, 2) NOT NULL, -- Importe final total a pagar (subtotal_amount + shipping_amount)
    notes TEXT, -- Observaciones adicionales del cliente o del vendedor POS
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL, -- Fecha y hora de emisión del pedido
    created_by INT NOT NULL, -- Identificador del usuario que generó la orden
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL, -- Fecha y hora de última actualización
    updated_by INT, -- Identificador del usuario que modificó la orden
    deleted_at TIMESTAMP, -- Marca de tiempo de anulación lógica (NULL = vigente)
    deleted_by INT, -- Identificador del usuario que anuló lógicamente la orden
    CONSTRAINT fk_orders_user FOREIGN KEY (user_id) REFERENCES users(id), -- Relación con cliente
    CONSTRAINT fk_orders_channel FOREIGN KEY (channel_id) REFERENCES order_channels(id), -- Relación con canal
    CONSTRAINT fk_orders_status FOREIGN KEY (status_id) REFERENCES order_statuses(id), -- Relación con estado
    CONSTRAINT uq_orders_number UNIQUE (order_number), -- Garantiza códigos de pedido únicos
    CONSTRAINT chk_orders_amounts CHECK (subtotal_amount >= 0 AND shipping_amount >= 0 AND total_amount >= 0) -- Valida montos positivos
);

-- Detalle de líneas de productos adquiridos en cada pedido con su tramo de precio aplicado
CREATE TABLE order_items (
    id SERIAL PRIMARY KEY, -- Identificador único autoincremental de la línea de pedido
    order_id INT NOT NULL, -- Clave foránea hacia la orden cabecera a la que pertenece este ítem
    product_variant_id INT NOT NULL, -- Clave foránea hacia la variante física (SKU) vendida
    pricing_tier_id INT NOT NULL, -- Clave foránea hacia pricing_tiers que documenta qué escala de precio se aplicó
    quantity INT NOT NULL, -- Cantidad de unidades compradas de esta variante
    unit_price DECIMAL(12, 2) NOT NULL, -- Precio unitario cobrado según el tramo de cantidad
    subtotal DECIMAL(12, 2) NOT NULL, -- Importe total de la línea (quantity * unit_price)
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL, -- Fecha y hora de registro del ítem
    created_by INT NOT NULL, -- Identificador del usuario creador
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL, -- Fecha y hora de última actualización
    updated_by INT, -- Identificador del usuario modificador
    deleted_at TIMESTAMP, -- Marca de tiempo de borrado lógico (NULL = activo)
    deleted_by INT, -- Identificador del usuario que ejecutó el borrado lógico
    CONSTRAINT fk_order_items_order FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE, -- Relación con orden cabecera
    CONSTRAINT fk_order_items_variant FOREIGN KEY (product_variant_id) REFERENCES product_variants(id), -- Relación con variante SKU
    CONSTRAINT fk_order_items_tier FOREIGN KEY (pricing_tier_id) REFERENCES pricing_tiers(id), -- Relación con tramo aplicado
    CONSTRAINT chk_order_items_qty CHECK (quantity > 0) -- La cantidad vendida debe ser mayor a cero
);

-- Registra y concilia las transacciones financieras de cobro asociadas a cada pedido
CREATE TABLE payments (
    id SERIAL PRIMARY KEY, -- Identificador único autoincremental del registro de pago
    order_id INT NOT NULL, -- Clave foránea hacia el pedido que se está pagando
    payment_method_id INT NOT NULL, -- Clave foránea hacia payment_methods (tarjeta, transferencia, efectivo, etc.)
    status_id INT NOT NULL, -- Clave foránea hacia payment_statuses (pendiente, confirmado, rechazado, reembolsado)
    transaction_reference VARCHAR(100), -- Número de operación bancaria, voucher POS o ID de pasarela
    amount_paid DECIMAL(12, 2) NOT NULL, -- Monto abonado en esta transacción
    paid_at TIMESTAMP, -- Fecha y hora exacta en que se confirmó el pago
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL, -- Fecha y hora de creación del registro de pago
    created_by INT NOT NULL, -- Identificador del usuario que registró el pago
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL, -- Fecha y hora de última actualización
    updated_by INT, -- Identificador del usuario modificador
    deleted_at TIMESTAMP, -- Marca de tiempo de borrado lógico (NULL = vigente)
    deleted_by INT, -- Identificador del usuario que ejecutó el borrado lógico
    CONSTRAINT fk_payments_order FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE, -- Relación con orden
    CONSTRAINT fk_payments_method FOREIGN KEY (payment_method_id) REFERENCES payment_methods(id), -- Relación con método de pago
    CONSTRAINT fk_payments_status FOREIGN KEY (status_id) REFERENCES payment_statuses(id), -- Relación con estado de pago
    CONSTRAINT chk_payments_amount CHECK (amount_paid >= 0) -- Valida monto no negativo
);

-- Controla la logística híbrida (retiro presencial en tienda sin costo o envío con seguimiento)
CREATE TABLE shipments (
    id SERIAL PRIMARY KEY, -- Identificador único autoincremental del despacho logístico
    order_id INT NOT NULL, -- Clave foránea hacia el pedido asociado al despacho
    fulfillment_type_id INT NOT NULL, -- Clave foránea hacia fulfillment_types (retiro_tienda, envio_domicilio, agencia)
    shipping_status_id INT NOT NULL, -- Clave foránea hacia shipping_statuses que rastrea el estado de entrega
    shipping_cost DECIMAL(12, 2) DEFAULT 0.00 NOT NULL, -- Costo cobrado por el despacho (0.00 para retiro en tienda)
    destination_address TEXT, -- Dirección física de entrega (NULL cuando es retiro presencial en tienda)
    city VARCHAR(100), -- Ciudad o departamento de destino logístico
    tracking_number VARCHAR(100), -- Código de seguimiento o guía de remisión de transporte
    dispatched_at TIMESTAMP, -- Fecha y hora en que el paquete salió de almacén
    delivered_at TIMESTAMP, -- Fecha y hora en que el cliente recibió o retiró el pedido
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL, -- Fecha y hora de creación de la orden logística
    created_by INT NOT NULL, -- Identificador del usuario creador
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL, -- Fecha y hora de última actualización
    updated_by INT, -- Identificador del usuario modificador
    deleted_at TIMESTAMP, -- Marca de tiempo de borrado lógico (NULL = activo)
    deleted_by INT, -- Identificador del usuario que ejecutó el borrado lógico
    CONSTRAINT fk_shipments_order FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE, -- Relación con orden
    CONSTRAINT fk_shipments_fulfillment FOREIGN KEY (fulfillment_type_id) REFERENCES fulfillment_types(id), -- Relación con modalidad
    CONSTRAINT fk_shipments_status FOREIGN KEY (shipping_status_id) REFERENCES shipping_statuses(id), -- Relación con estado logístico
    CONSTRAINT chk_shipments_cost CHECK (shipping_cost >= 0) -- El costo de envío no puede ser negativo
);

-- =============================================================================
-- MÓDULO 7: BRANDING CORPORATIVO E IDENTIDAD VISUAL DINÁMICA
-- =============================================================================

-- Almacena los datos institucionales, fiscales y canales de atención directa de la empresa propietaria
CREATE TABLE company_profiles (
    id SERIAL PRIMARY KEY, -- Identificador único autoincremental del perfil institucional
    company_name VARCHAR(150) NOT NULL, -- Razón social o nombre comercial oficial de la empresa
    tax_id VARCHAR(50) NOT NULL, -- RUC o número de identificación tributaria (ej. 20601234567)
    address TEXT, -- Dirección fiscal y sede principal de operaciones
    phone_primary VARCHAR(30), -- Teléfono central de atención al cliente
    whatsapp_contact VARCHAR(30), -- Número oficial de WhatsApp para ventas y soporte directo
    support_email VARCHAR(100), -- Correo electrónico corporativo de soporte técnico y comercial
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL, -- Fecha y hora de creación del perfil
    created_by INT NOT NULL, -- Identificador del usuario creador
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL, -- Fecha y hora de última actualización
    updated_by INT, -- Identificador del usuario modificador
    deleted_at TIMESTAMP, -- Marca de tiempo de borrado lógico (NULL = activo)
    deleted_by INT -- Identificador del usuario que ejecutó el borrado lógico
);

-- Almacena de forma normalizada (1FN y 3FN) las múltiples redes sociales de la empresa
CREATE TABLE social_networks (
    id SERIAL PRIMARY KEY, -- Identificador único autoincremental de la red social
    company_profile_id INT NOT NULL, -- Clave foránea hacia company_profiles que vincula la red con la empresa
    network_name VARCHAR(50) NOT NULL, -- Nombre de la plataforma social (Instagram, Facebook, TikTok, LinkedIn)
    profile_url VARCHAR(255) NOT NULL, -- Enlace URL completo hacia la página oficial de la empresa
    icon_identifier VARCHAR(50), -- Identificador de clase o ícono vectorial para renderizado en UI
    is_active BOOLEAN DEFAULT TRUE NOT NULL, -- Controla si el enlace se muestra en el portal público
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL, -- Fecha y hora de registro
    created_by INT NOT NULL, -- Identificador del usuario creador
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL, -- Fecha y hora de última modificación
    updated_by INT, -- Identificador del usuario modificador
    deleted_at TIMESTAMP, -- Marca de tiempo de borrado lógico (NULL = vigente)
    deleted_by INT, -- Identificador del usuario que ejecutó el borrado lógico
    CONSTRAINT fk_social_company FOREIGN KEY (company_profile_id) REFERENCES company_profiles(id) ON DELETE CASCADE -- Relación con empresa
);

-- Almacena paquetes gráficos históricos de marca garantizando un único paquete activo por empresa
CREATE TABLE brand_assets (
    id SERIAL PRIMARY KEY, -- Identificador único autoincremental del paquete gráfico
    company_profile_id INT NOT NULL, -- Clave foránea hacia company_profiles
    asset_name VARCHAR(100) NOT NULL, -- Nombre descriptivo de la versión gráfica (ej. Identidad Oficial 2026)
    logo_light_url VARCHAR(255) NOT NULL, -- URL del logotipo principal optimizado para fondos claros
    logo_dark_url VARCHAR(255), -- URL del logotipo alternativo optimizado para fondos oscuros
    isotype_url VARCHAR(255), -- URL del símbolo o isotipo compacto de la marca
    favicon_url VARCHAR(255), -- URL del ícono de pestaña del navegador web
    is_active BOOLEAN DEFAULT FALSE NOT NULL, -- Indica si es el paquete gráfico vigente (máximo 1 activo por empresa)
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL, -- Fecha y hora de carga del paquete
    created_by INT NOT NULL, -- Identificador del usuario creador
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL, -- Fecha y hora de última actualización
    updated_by INT, -- Identificador del usuario modificador
    deleted_at TIMESTAMP, -- Marca de tiempo de borrado lógico (NULL = disponible)
    deleted_by INT, -- Identificador del usuario que ejecutó el borrado lógico
    CONSTRAINT fk_brand_assets_company FOREIGN KEY (company_profile_id) REFERENCES company_profiles(id) ON DELETE CASCADE -- Relación con empresa
);

-- Índice único parcial: Garantiza a nivel de motor SQL que solo exista 1 paquete de brand_assets activo por empresa
CREATE UNIQUE INDEX idx_unique_active_brand_asset
ON brand_assets (company_profile_id)
WHERE is_active = TRUE AND deleted_at IS NULL;

-- Catálogo maestro de paletas de colores visuales con conmutación dinámica en tiempo real
CREATE TABLE color_palettes (
    id SERIAL PRIMARY KEY, -- Identificador único autoincremental de la paleta visual
    name VARCHAR(100) NOT NULL, -- Nombre único de la paleta (ej. Ejecutivo Deportivo, Campaña Cyber Verano)
    description TEXT, -- Descripción del concepto estético y contraste de la paleta
    is_active BOOLEAN DEFAULT FALSE NOT NULL, -- Indica si es la paleta activa global en vistas públicas y admin
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL, -- Fecha y hora de creación de la paleta
    created_by INT NOT NULL, -- Identificador del usuario creador
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL, -- Fecha y hora de última actualización
    updated_by INT, -- Identificador del usuario modificador
    deleted_at TIMESTAMP, -- Marca de tiempo de borrado lógico (NULL = disponible)
    deleted_by INT, -- Identificador del usuario que ejecutó el borrado lógico
    CONSTRAINT uq_color_palettes_name UNIQUE (name) -- Evita paletas con nombres duplicados
);

-- Índice único parcial global: Garantiza que exista como máximo una paleta de colores activa a la vez en toda la plataforma
CREATE UNIQUE INDEX idx_unique_active_color_palette
ON color_palettes ((1))
WHERE is_active = TRUE AND deleted_at IS NULL;

-- Almacena los tokens semánticos CSS (Design Tokens) vinculados a cada paleta para evitar código hardcodeado
CREATE TABLE design_tokens (
    id SERIAL PRIMARY KEY, -- Identificador único autoincremental del conjunto de tokens
    color_palette_id INT NOT NULL, -- Clave foránea única hacia color_palettes (relación 1:1 por paleta)
    primary_color VARCHAR(10) NOT NULL, -- Color primario institucional en formato hexadecimal (ej. #0F172A)
    secondary_color VARCHAR(10) NOT NULL, -- Color secundario de apoyo visual (ej. #334155)
    accent_color VARCHAR(10) NOT NULL, -- Color de acento para elementos destacados y ofertas (ej. #2563EB)
    background_primary VARCHAR(10) NOT NULL, -- Color de fondo general de las pantallas (ej. #F8FAFC)
    background_secondary VARCHAR(10) NOT NULL, -- Color de fondo secundario para secciones alternas (ej. #F1F5F9)
    surface_card VARCHAR(10) NOT NULL, -- Color de superficie para tarjetas, paneles y modales (ej. #FFFFFF)
    text_primary VARCHAR(10) NOT NULL, -- Color de texto principal de alto contraste (ej. #0F172A)
    text_secondary VARCHAR(10) NOT NULL, -- Color de texto secundario para subtítulos y etiquetas (ej. #64748B)
    font_family_base VARCHAR(100) NOT NULL, -- Familia tipográfica principal inyectada al DOM (ej. 'Inter', sans-serif)
    border_color VARCHAR(10) NOT NULL, -- Color estándar para bordes y líneas divisoras (ej. #E2E8F0)
    button_primary_bg VARCHAR(10) NOT NULL, -- Color de fondo para botones de acción principal (ej. #2563EB)
    button_primary_text VARCHAR(10) NOT NULL, -- Color de texto sobre botones principales (ej. #FFFFFF)
    color_success VARCHAR(10) NOT NULL, -- Token semántico para confirmaciones y estados exitosos (ej. #16A34A)
    color_warning VARCHAR(10) NOT NULL, -- Token semántico para advertencias y alertas preventivas (ej. #D97706)
    color_error VARCHAR(10) NOT NULL, -- Token semántico para errores críticos y validaciones fallidas (ej. #DC2626)
    color_info VARCHAR(10) NOT NULL, -- Token semántico para mensajes informativos (ej. #0284C7)
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL, -- Fecha y hora de creación de los tokens
    created_by INT NOT NULL, -- Identificador del usuario creador
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL, -- Fecha y hora de última actualización
    updated_by INT, -- Identificador del usuario modificador
    deleted_at TIMESTAMP, -- Marca de tiempo de borrado lógico (NULL = activo)
    deleted_by INT, -- Identificador del usuario que ejecutó el borrado lógico
    CONSTRAINT fk_design_tokens_palette FOREIGN KEY (color_palette_id) REFERENCES color_palettes(id) ON DELETE CASCADE, -- Relación con paleta
    CONSTRAINT uq_design_tokens_palette UNIQUE (color_palette_id) -- Un conjunto único de tokens por paleta
);

-- =============================================================================
-- MÓDULO 8: AUDITORÍA CENTRALIZADA INMUTABLE (FASE 1 — SECCIÓN 2.9)
-- =============================================================================

-- Bitácora centralizada e inmutable que registra eventos críticos con instantáneas JSONB
CREATE TABLE audit_logs (
    id BIGSERIAL PRIMARY KEY, -- Identificador secuencial de alta capacidad (64 bits) para auditoría masiva
    table_name VARCHAR(100) NOT NULL, -- Nombre técnico de la tabla auditada (ej. products, orders, color_palettes)
    record_id INT NOT NULL, -- Identificador primario del registro afectado en la tabla auditada
    action VARCHAR(20) NOT NULL, -- Tipo de operación auditada (INSERT, UPDATE, SOFT_DELETE)
    old_values JSONB, -- Instantánea JSONB con los valores anteriores a la modificación (NULL en INSERT)
    new_values JSONB, -- Instantánea JSONB con los valores posteriores a la operación
    user_id INT NOT NULL, -- Identificador del usuario que ejecutó la acción auditada
    ip_address VARCHAR(45), -- Dirección IPv4 o IPv6 desde donde se originó la petición
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL -- Marca de tiempo exacta e inalterable del evento
);

-- =============================================================================
-- SECCIÓN 9: VISTAS ANALÍTICAS, FUNCIONES, TRIGGERS E ÍNDICES DE RENDIMIENTO
-- =============================================================================

-- Vista analítica que consolida el catálogo activo, variantes, atributos maestros y existencias
CREATE OR REPLACE VIEW vw_active_catalog_inventory AS
SELECT
    p.id AS product_id,
    p.name AS product_name,
    p.slug AS product_slug,
    b.name AS brand_name,
    c.name AS category_name,
    ds.name AS demographic_segment,
    tg.name AS target_gender,
    pv.id AS variant_id,
    pv.sku,
    col.name AS color_name,
    col.hex_code AS color_hex,
    mat.name AS material_name,
    sz.size_type,
    sz.size_value,
    pv.base_price,
    pv.stock_current,
    COALESCE(sac.min_threshold, 0) AS min_stock_threshold,
    (pv.stock_current <= COALESCE(sac.min_threshold, 0)) AS is_low_stock
FROM products p
INNER JOIN brands b ON p.brand_id = b.id
INNER JOIN categories c ON p.category_id = c.id
INNER JOIN demographic_segments ds ON p.demographic_segment_id = ds.id
INNER JOIN target_genders tg ON p.target_gender_id = tg.id
INNER JOIN product_variants pv ON pv.product_id = p.id
INNER JOIN colors col ON pv.color_id = col.id
INNER JOIN materials mat ON pv.material_id = mat.id
INNER JOIN sizes sz ON pv.size_id = sz.id
LEFT JOIN stock_alerts_config sac ON sac.product_variant_id = pv.id AND sac.deleted_at IS NULL
WHERE p.deleted_at IS NULL
  AND p.is_published = TRUE
  AND pv.deleted_at IS NULL
  AND pv.is_active = TRUE;

-- Vista operativa que consolida pedidos, clientes, canales, pagos y logística híbrida
CREATE OR REPLACE VIEW vw_sales_summary_report AS
SELECT
    o.id AS order_id,
    o.order_number,
    o.created_at AS order_date,
    u.first_name || ' ' || u.last_name AS customer_name,
    u.email AS customer_email,
    oc.name AS sales_channel,
    os.name AS order_status,
    o.subtotal_amount,
    o.shipping_amount,
    o.total_amount,
    pm.name AS payment_method,
    ps.name AS payment_status,
    ft.name AS fulfillment_type,
    ss.name AS shipping_status,
    sh.tracking_number
FROM orders o
INNER JOIN users u ON o.user_id = u.id
INNER JOIN order_channels oc ON o.channel_id = oc.id
INNER JOIN order_statuses os ON o.status_id = os.id
LEFT JOIN payments pay ON pay.order_id = o.id AND pay.deleted_at IS NULL
LEFT JOIN payment_methods pm ON pay.payment_method_id = pm.id
LEFT JOIN payment_statuses ps ON pay.status_id = ps.id
LEFT JOIN shipments sh ON sh.order_id = o.id AND sh.deleted_at IS NULL
LEFT JOIN fulfillment_types ft ON sh.fulfillment_type_id = ft.id
LEFT JOIN shipping_statuses ss ON sh.shipping_status_id = ss.id
WHERE o.deleted_at IS NULL;

-- Función almacenada que actualiza automáticamente la columna updated_at ante cualquier modificación
CREATE OR REPLACE FUNCTION fn_update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at := CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Triggers para automatizar la actualización de updated_at en entidades principales
CREATE TRIGGER trg_users_updated_at BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION fn_update_updated_at();
CREATE TRIGGER trg_products_updated_at BEFORE UPDATE ON products FOR EACH ROW EXECUTE FUNCTION fn_update_updated_at();
CREATE TRIGGER trg_variants_updated_at BEFORE UPDATE ON product_variants FOR EACH ROW EXECUTE FUNCTION fn_update_updated_at();
CREATE TRIGGER trg_orders_updated_at BEFORE UPDATE ON orders FOR EACH ROW EXECUTE FUNCTION fn_update_updated_at();
CREATE TRIGGER trg_palettes_updated_at BEFORE UPDATE ON color_palettes FOR EACH ROW EXECUTE FUNCTION fn_update_updated_at();

-- Función almacenada que garantiza la inmutabilidad estricta del Kardex Comercial y Audit Logs
CREATE OR REPLACE FUNCTION fn_prevent_immutable_modification()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'Operación prohibida: La tabla % es un registro histórico inmutable y no admite UPDATE ni DELETE.', TG_TABLE_NAME;
END;
$$ LANGUAGE plpgsql;

-- Triggers de inmutabilidad aplicados a inventory_movements y audit_logs
CREATE TRIGGER trg_immutable_kardex
BEFORE UPDATE OR DELETE ON inventory_movements
FOR EACH ROW EXECUTE FUNCTION fn_prevent_immutable_modification();

CREATE TRIGGER trg_immutable_audit_logs
BEFORE UPDATE OR DELETE ON audit_logs
FOR EACH ROW EXECUTE FUNCTION fn_prevent_immutable_modification();

-- Índices compuestos y parciales para optimizar consultas críticas en producción
CREATE INDEX idx_products_brand_cat ON products (brand_id, category_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_variants_sku ON product_variants (sku) WHERE deleted_at IS NULL;
CREATE INDEX idx_kardex_variant_date ON inventory_movements (product_variant_id, created_at DESC);
CREATE INDEX idx_orders_user_status ON orders (user_id, status_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_audit_logs_table_record ON audit_logs (table_name, record_id, created_at DESC);

-- =============================================================================
-- SECCIÓN 10: CARGA COMPLETA DE DATOS SINTÉTICOS (36 TABLAS SIN EXCEPCIÓN)
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 10.1. Poblado del Módulo 1: Roles, Permisos, Asignaciones y Usuarios
-- -----------------------------------------------------------------------------
INSERT INTO roles (id, name, description, is_system_role, created_by) VALUES
(1, 'Super Administrador', 'Acceso total sin restricciones a todos los módulos ERP, seguridad y branding.', TRUE, 1),
(2, 'Gerente Comercial', 'Gestión de catálogo, precios escalonados, reportes de ventas y promociones.', FALSE, 1),
(3, 'Almacenero / Logística', 'Control de inventario, movimientos de Kardex, recepción de compras y despachos.', FALSE, 1),
(4, 'Vendedor POS', 'Registro de ventas presenciales en tienda, consulta de stock y emisión de pedidos.', FALSE, 1),
(5, 'Cliente Mayorista B2B', 'Comprador corporativo o club deportivo con acceso a precios por volumen.', FALSE, 1),
(6, 'Cliente Minorista B2C', 'Comprador final de tienda electrónica minorista.', TRUE, 1);

INSERT INTO permissions (id, code, module, description, created_by) VALUES
(1, 'users.manage', 'users', 'Crear, editar, suspender y asignar roles a usuarios del sistema', 1),
(2, 'catalog.manage', 'catalog', 'Administrar marcas, categorías, productos, variantes e imágenes', 1),
(3, 'pricing.manage', 'pricing', 'Configurar tramos de cantidad y listas de precios B2B/B2C', 1),
(4, 'bulk_import.execute', 'bulk_import', 'Subir archivos masivos CSV/Excel y revisar reportes de errores', 1),
(5, 'kardex.read', 'inventory', 'Consultar historial inmutable de movimientos de inventario y alertas', 1),
(6, 'kardex.create', 'inventory', 'Registrar entradas por compra y ajustes autorizados de inventario', 1),
(7, 'orders.create', 'sales', 'Generar órdenes de compra en tienda web o punto de venta POS', 1),
(8, 'orders.manage', 'sales', 'Confirmar pagos, actualizar estados de pedido y gestionar envíos', 1),
(9, 'branding.manage', 'branding', 'Modificar perfil institucional, logotipos y paletas dinámicas', 1),
(10, 'audit.read', 'security', 'Auditar bitácora inmutable de eventos del sistema', 1);

INSERT INTO role_permissions (role_id, permission_id, created_by) VALUES
-- Super Administrador (Todos los permisos)
(1, 1, 1), (1, 2, 1), (1, 3, 1), (1, 4, 1), (1, 5, 1),
(1, 6, 1), (1, 7, 1), (1, 8, 1), (1, 9, 1), (1, 10, 1),
-- Gerente Comercial
(2, 2, 1), (2, 3, 1), (2, 4, 1), (2, 5, 1), (2, 8, 1), (2, 9, 1),
-- Almacenero / Logística
(3, 5, 1), (3, 6, 1), (3, 8, 1),
-- Vendedor POS
(4, 5, 1), (4, 7, 1),
-- Cliente Mayorista B2B y Minorista B2C
(5, 7, 1),
(6, 7, 1);

-- Inserción de usuarios con hashes Bcrypt reales generados mediante pgcrypto (crypt + gen_salt('bf', 10))
INSERT INTO users (id, role_id, first_name, last_name, email, document_type, document_number, phone, password_hash, is_active, last_login_at, created_by) VALUES
-- Contraseña en texto plano: AdminSport#2026!
(1, 1, 'Carlos', 'Mendoza Ríos', 'admin@sportcorp.pe', 'DNI', '41892345', '+51 999 888 101', crypt('AdminSport#2026!', gen_salt('bf', 10)), TRUE, CURRENT_TIMESTAMP - INTERVAL '1 hour', 1),
-- Contraseña en texto plano: VentasPro#2026!
(2, 2, 'Lucía', 'Fernández Salazar', 'comercial@sportcorp.pe', 'DNI', '44561289', '+51 999 888 102', crypt('VentasPro#2026!', gen_salt('bf', 10)), TRUE, CURRENT_TIMESTAMP - INTERVAL '3 hours', 1),
-- Contraseña en texto plano: KardexSafe#2026!
(3, 3, 'Jorge', 'Huamán Quispe', 'almacen@sportcorp.pe', 'DNI', '40127834', '+51 999 888 103', crypt('KardexSafe#2026!', gen_salt('bf', 10)), TRUE, CURRENT_TIMESTAMP - INTERVAL '5 hours', 1),
-- Contraseña en texto plano: CajaTienda#2026!
(4, 4, 'Andrea', 'Paredes Vargas', 'pos.lima@sportcorp.pe', 'DNI', '46789012', '+51 999 888 104', crypt('CajaTienda#2026!', gen_salt('bf', 10)), TRUE, CURRENT_TIMESTAMP - INTERVAL '30 minutes', 1),
-- Contraseña en texto plano: MayoristaB2B#2026!
(5, 5, 'Roberto', 'Salas — Club Atlético Lima', 'compras@clubatletico.pe', 'RUC', '20548912341', '+51 987 654 321', crypt('MayoristaB2B#2026!', gen_salt('bf', 10)), TRUE, CURRENT_TIMESTAMP - INTERVAL '1 day', 1),
-- Contraseña en texto plano: ClienteB2C#2026!
(6, 6, 'Valeria', 'Mendoza Castillo', 'valeria.mendoza@gmail.com', 'DNI', '71234568', '+51 945 123 789', crypt('ClienteB2C#2026!', gen_salt('bf', 10)), TRUE, CURRENT_TIMESTAMP - INTERVAL '2 days', 1);

-- -----------------------------------------------------------------------------
-- 10.2. Poblado del Módulo 2: Maestros de Catálogo, Productos, Variantes e Imágenes
-- -----------------------------------------------------------------------------
INSERT INTO brands (id, name, slug, description, logo_url, is_active, created_by) VALUES
(1, 'Nike', 'nike', 'Equipamiento deportivo de alto rendimiento, running y fútbol profesional.', '/assets/brands/nike.svg', TRUE, 1),
(2, 'Adidas', 'adidas', 'Calzado e indumentaria deportiva internacional con tecnología Aeroready.', '/assets/brands/adidas.svg', TRUE, 1),
(3, 'Puma', 'puma', 'Innovación en calzado deportivo, entrenamiento y ropa urbana.', '/assets/brands/puma.svg', TRUE, 1),
(4, 'Under Armour', 'under-armour', 'Ropa técnica de compresión y entrenamiento funcional.', '/assets/brands/under-armour.svg', TRUE, 1);

INSERT INTO categories (id, parent_id, name, slug, description, is_active, created_by) VALUES
(1, NULL, 'Calzado Deportivo', 'calzado-deportivo', 'Zapatillas y botines especializados por disciplina', TRUE, 1),
(2, NULL, 'Indumentaria', 'indumentaria', 'Camisetas, shorts, casacas y conjuntos deportivos', TRUE, 1),
(3, NULL, 'Accesorios Deportivos', 'accesorios-deportivos', 'Mochilas, balones, gorras y equipamiento complementario', TRUE, 1),
(4, 1, 'Running & Maratón', 'running-maraton', 'Zapatillas con amortiguación reactiva para asfalto y pista', TRUE, 1),
(5, 1, 'Fútbol', 'futbol', 'Chimpunes y zapatillas de futsal de alta tracción', TRUE, 1),
(6, 2, 'Camisetas Técnicas', 'camisetas-tecnicas', 'Polos deportivos transpirables de secado rápido', TRUE, 1);

INSERT INTO demographic_segments (id, name, description, created_by) VALUES
(1, 'adultos', 'Línea diseñada para jóvenes y adultos con tallaje estándar', 1),
(2, 'ninos', 'Línea infantil y junior con ergonomía adaptada', 1),
(3, 'sin_clasificacion', 'Artículos universales que no distinguen grupo etario (mochilas, balones)', 1);

INSERT INTO target_genders (id, name, description, created_by) VALUES
(1, 'hombre', 'Diseño y horma anatómica masculina', 1),
(2, 'mujer', 'Diseño y horma anatómica femenina', 1),
(3, 'unisex', 'Diseño versátil apto para cualquier género', 1),
(4, 'n_a', 'No aplica clasificación de género (accesorios y equipamiento)', 1);

INSERT INTO colors (id, name, hex_code, created_by) VALUES
(1, 'Negro Ébano', '#111827', 1),
(2, 'Blanco Puro', '#FFFFFF', 1),
(3, 'Azul Eléctrico', '#2563EB', 1),
(4, 'Rojo Carmesí', '#DC2626', 1),
(5, 'Verde Neón', '#16A34A', 1),
(6, 'Gris Grafito', '#4B5563', 1);

INSERT INTO materials (id, name, description, created_by) VALUES
(1, 'Malla Engineered Mesh', 'Tejido sintético ultraligero de máxima ventilación', 1),
(2, 'Poliéster Reciclado Dry-Fit', 'Fibra técnica que absorbe y evapora la humedad corporal', 1),
(3, 'Cuero Sintético Microfibra', 'Material resistente a la abrasión con control de balón', 1),
(4, 'Poliuretano Termoplástico (TPU)', 'Compuesto de alta durabilidad para balones y refuerzos', 1),
(5, 'Lona Ripstop Impermeable', 'Tejido antidesgarro resistente al agua para mochilas', 1);

INSERT INTO sizes (id, size_type, size_value, sort_order, created_by) VALUES
(1, 'alfabetico', 'S', 1, 1),
(2, 'alfabetico', 'M', 2, 1),
(3, 'alfabetico', 'L', 3, 1),
(4, 'alfabetico', 'XL', 4, 1),
(5, 'calzado', '38', 10, 1),
(6, 'calzado', '40', 11, 1),
(7, 'calzado', '41', 12, 1),
(8, 'calzado', '42', 13, 1),
(9, 'numerico_ninos', '8', 20, 1),
(10, 'numerico_ninos', '10', 21, 1),
(11, 'talla_unica', 'Única', 30, 1);

INSERT INTO products (id, brand_id, category_id, demographic_segment_id, target_gender_id, name, slug, description, is_published, created_by) VALUES
(1, 1, 4, 1, 1, 'Nike Air Zoom Pegasus 41', 'nike-air-zoom-pegasus-41', 'Zapatilla de running diario con doble unidad Air Zoom y espuma ReactX.', TRUE, 1),
(2, 2, 4, 1, 2, 'Adidas Ultraboost Light Mujer', 'adidas-ultraboost-light-mujer', 'Amortiguación Light BOOST un 30% más ligera para carreras de larga distancia.', TRUE, 1),
(3, 1, 5, 1, 1, 'Nike Mercurial Vapor 15 Academy', 'nike-mercurial-vapor-15-academy', 'Chimpunes diseñados para velocidad explosiva en césped natural y sintético.', TRUE, 1),
(4, 2, 6, 1, 3, 'Camiseta Entrenamiento Adidas Tiro 24', 'camiseta-adidas-tiro-24', 'Camiseta oficial de entrenamiento con tecnología AEROREADY para clubes.', TRUE, 2),
(5, 4, 6, 1, 1, 'Polo Compresión Under Armour HeatGear', 'polo-compresion-ua-heatgear', 'Prenda base ultra ajustada que mantiene el músculo fresco bajo alta exigencia.', TRUE, 2),
(6, 3, 6, 2, 3, 'Conjunto Deportivo Puma Junior', 'conjunto-deportivo-puma-junior', 'Set ligero de entrenamiento infantil de secado rápido.', TRUE, 2),
(7, 1, 3, 3, 4, 'Mochila Deportiva Nike Brasilia 9.5 (24L)', 'mochila-nike-brasilia-24l', 'Mochila resistente con compartimento acolchado para laptop y calzado.', TRUE, 1),
(8, 2, 3, 3, 4, 'Balón Profesional Adidas Al Rihla Pro N°5', 'balon-adidas-pro-5', 'Balón termosellado sin costuras certificado para competición oficial.', TRUE, 1);

-- Variantes físicas (16 SKUs) con stock_current inicial en 0 antes de aplicar el Kardex histórico
INSERT INTO product_variants (id, product_id, color_id, material_id, size_id, sku, base_price, stock_current, is_active, created_by) VALUES
(1, 1, 1, 1, 7, 'NK-PEG41-NEG-41', 489.90, 45, TRUE, 1),
(2, 1, 1, 1, 8, 'NK-PEG41-NEG-42', 489.90, 32, TRUE, 1),
(3, 1, 3, 1, 7, 'NK-PEG41-AZU-41', 489.90, 18, TRUE, 1),
(4, 2, 2, 1, 5, 'AD-UBLT-BLA-38', 549.00, 24, TRUE, 1),
(5, 2, 4, 1, 5, 'AD-UBLT-ROJ-38', 549.00, 4, TRUE, 1),  -- Stock bajo umbral (alerta activa)
(6, 3, 5, 3, 6, 'NK-MERC15-VER-40', 359.90, 28, TRUE, 1),
(7, 3, 5, 3, 7, 'NK-MERC15-VER-41', 359.90, 15, TRUE, 1),
(8, 4, 1, 2, 2, 'AD-TIRO24-NEG-M', 119.90, 120, TRUE, 2),
(9, 4, 1, 2, 3, 'AD-TIRO24-NEG-L', 119.90, 95, TRUE, 2),
(10, 4, 3, 2, 2, 'AD-TIRO24-AZU-M', 119.90, 80, TRUE, 2),
(11, 5, 6, 2, 2, 'UA-HGEAR-GRI-M', 139.00, 40, TRUE, 2),
(12, 5, 6, 2, 3, 'UA-HGEAR-GRI-L', 139.00, 3, TRUE, 2),   -- Stock bajo umbral (alerta activa)
(13, 6, 4, 2, 9, 'PM-JRSET-ROJ-08', 149.90, 30, TRUE, 2),
(14, 6, 4, 2, 10, 'PM-JRSET-ROJ-10', 149.90, 25, TRUE, 2),
(15, 7, 1, 5, 11, 'NK-BRAS24-NEG-UNI', 159.90, 50, TRUE, 1),
(16, 8, 2, 4, 11, 'AD-BALPRO-BLA-UNI', 229.00, 35, TRUE, 1);

INSERT INTO product_images (product_id, product_variant_id, image_url, alt_text, is_primary, sort_order, created_by) VALUES
(1, 1, '/uploads/products/nk-pegasus-41-black-main.webp', 'Nike Air Zoom Pegasus 41 Negro Vista Lateral', TRUE, 1, 1),
(1, 3, '/uploads/products/nk-pegasus-41-blue.webp', 'Nike Air Zoom Pegasus 41 Azul Eléctrico', FALSE, 2, 1),
(2, 4, '/uploads/products/ad-ultraboost-white.webp', 'Adidas Ultraboost Light Blanco Mujer', TRUE, 1, 1),
(3, 6, '/uploads/products/nk-mercurial-neon.webp', 'Nike Mercurial Vapor 15 Verde Neón', TRUE, 1, 1),
(4, 8, '/uploads/products/ad-tiro24-black.webp', 'Camiseta Adidas Tiro 24 Negra', TRUE, 1, 2),
(5, 11, '/uploads/products/ua-heatgear-grey.webp', 'Polo Compresión Under Armour Gris', TRUE, 1, 2),
(6, 13, '/uploads/products/puma-junior-red.webp', 'Conjunto Deportivo Puma Junior Rojo', TRUE, 1, 2),
(7, 15, '/uploads/products/nk-brasilia-backpack.webp', 'Mochila Nike Brasilia 24L Negra', TRUE, 1, 1),
(8, 16, '/uploads/products/ad-alrihla-ball.webp', 'Balón Profesional Adidas N°5', TRUE, 1, 1);

-- -----------------------------------------------------------------------------
-- 10.3. Poblado del Módulo 3: Tramos de Cantidad y Precios Escalonados B2B/B2C
-- -----------------------------------------------------------------------------
INSERT INTO pricing_tiers (id, tier_name, min_quantity, max_quantity, description, created_by) VALUES
(1, 'Minorista', 1, 5, 'Precio público estándar para compras de 1 a 5 unidades', 1),
(2, 'Mayorista 1', 6, 11, 'Descuento corporativo nivel 1 para compras de 6 a 11 unidades', 1),
(3, 'Mayorista 2', 12, 23, 'Descuento corporativo nivel 2 para compras de 12 a 23 unidades', 1),
(4, 'Mayorista 3', 24, NULL, 'Tarifa preferencial máxima para clubes y distribuidores (24 unidades a más)', 1);

INSERT INTO product_volume_prices (product_variant_id, pricing_tier_id, unit_price, created_by) VALUES
-- Variante 1: Nike Pegasus 41 Negro Talla 41 (Base 489.90)
(1, 1, 489.90, 1), (1, 2, 455.00, 1), (1, 3, 429.00, 1), (1, 4, 399.00, 1),
-- Variante 8: Camiseta Adidas Tiro 24 Negra M (Base 119.90)
(8, 1, 119.90, 2), (8, 2, 105.00, 2), (8, 3, 95.00, 2), (8, 4, 85.00, 2),
-- Variante 9: Camiseta Adidas Tiro 24 Negra L (Base 119.90)
(9, 1, 119.90, 2), (9, 2, 105.00, 2), (9, 3, 95.00, 2), (9, 4, 85.00, 2),
-- Variante 15: Mochila Nike Brasilia 24L (Base 159.90)
(15, 1, 159.90, 1), (15, 2, 145.00, 1), (15, 3, 132.00, 1), (15, 4, 119.00, 1),
-- Variante 16: Balón Adidas Pro N°5 (Base 229.00)
(16, 1, 229.00, 1), (16, 2, 209.00, 1), (16, 3, 195.00, 1), (16, 4, 179.00, 1);

-- -----------------------------------------------------------------------------
-- 10.4. Poblado del Módulo 4: Cargas Masivas Asíncronas y Reportes Fail-Fast
-- -----------------------------------------------------------------------------
INSERT INTO bulk_import_jobs (id, user_id, file_name, import_type, status, total_rows, success_rows, error_rows, started_at, finished_at, created_by) VALUES
(1, 2, 'catalogo_nike_q2_2026.csv', 'variantes', 'exitoso', 50, 50, 0, CURRENT_TIMESTAMP - INTERVAL '5 days', CURRENT_TIMESTAMP - INTERVAL '5 days' + INTERVAL '14 seconds', 2),
(2, 2, 'actualizacion_tarifas_b2b.xlsx', 'precios', 'completado_con_errores', 40, 38, 2, CURRENT_TIMESTAMP - INTERVAL '2 days', CURRENT_TIMESTAMP - INTERVAL '2 days' + INTERVAL '9 seconds', 2),
(3, 3, 'nuevos_productos_sin_marca.csv', 'productos', 'rechazado', 15, 0, 15, CURRENT_TIMESTAMP - INTERVAL '1 day', CURRENT_TIMESTAMP - INTERVAL '1 day' + INTERVAL '2 seconds', 3);

INSERT INTO bulk_import_errors (bulk_import_job_id, row_number, row_data, error_message, created_by) VALUES
(2, 14, 'NK-PEG41-NEG-41;Mayorista 5;350.00', 'Validación Fail-Fast: El tramo de precio "Mayorista 5" no existe en la tabla maestra pricing_tiers.', 2),
(2, 29, 'AD-TIRO24-NEG-M;Mayorista 2;-15.00', 'Validación Fail-Fast: El precio unitario (-15.00) viola la restricción de importe positivo.', 2),
(3, 2, 'Zapatilla Runner X;Reebok;Calzado Deportivo', 'Validación Fail-Fast: La marca "Reebok" no se encuentra registrada previamente en la tabla maestra brands.', 3);

-- -----------------------------------------------------------------------------
-- 10.5. Poblado del Módulo 5: Kardex Comercial Inmutable y Alertas de Stock
-- Nota: Se insertan movimientos cuadrando matemáticamente con stock_current
-- -----------------------------------------------------------------------------
INSERT INTO inventory_movements (product_variant_id, movement_type, quantity, previous_stock, new_stock, reference_document, notes, created_by) VALUES
-- Variante 1 (Saldo final = 45): Compra 50 - Venta 5 = 45
(1, 'entrada_compra', 50, 0, 50, 'OC-2026-0101', 'Ingreso inicial de mercadería importada Nike Perú', 3),
(1, 'salida_venta', 5, 50, 45, 'PED-2026-0001', 'Despacho de pedido B2C/B2B confirmado', 4),
-- Variante 2 (Saldo final = 32): Compra 35 - Venta 3 = 32
(2, 'entrada_compra', 35, 0, 35, 'OC-2026-0101', 'Ingreso inicial de lote talla 42', 3),
(2, 'salida_venta', 3, 35, 32, 'PED-2026-0003', 'Venta presencial en tienda Miraflores', 4),
-- Variante 5 (Saldo final = 4): Compra 10 - Venta 6 = 4 (Dispara alerta por umbral 8)
(5, 'entrada_compra', 10, 0, 10, 'OC-2026-0104', 'Ingreso lote Adidas Mujer Rojo', 3),
(5, 'salida_venta', 6, 10, 4, 'PED-2026-0004', 'Venta web minorista', 2),
-- Variante 8 (Saldo final = 120): Compra 150 - Venta 30 = 120
(8, 'entrada_compra', 150, 0, 150, 'OC-2026-0108', 'Abastecimiento mayorista camisetas Tiro 24', 3),
(8, 'salida_venta', 30, 150, 120, 'PED-2026-0002', 'Pedido mayorista Club Atlético Lima (Tramo Mayorista 3)', 2),
-- Variante 12 (Saldo final = 3): Compra 10 - Venta 6 - Ajuste 1 = 3 (Dispara alerta por umbral 5)
(12, 'entrada_compra', 10, 0, 10, 'OC-2026-0112', 'Ingreso Under Armour HeatGear', 3),
(12, 'salida_venta', 6, 10, 4, 'PED-2026-0005', 'Venta corporativa', 2),
(12, 'ajuste_inventario', 1, 4, 3, 'AJU-2026-001', 'Merma detectada en control de calidad de almacén', 3),
-- Variante 16 (Saldo final = 35): Compra 40 - Venta 7 + Devolución 2 = 35
(16, 'entrada_compra', 40, 0, 40, 'OC-2026-0115', 'Ingreso balones oficiales Al Rihla', 3),
(16, 'salida_venta', 7, 40, 33, 'PED-2026-0002', 'Venta mayorista junto con indumentaria', 2),
(16, 'devolucion', 2, 33, 35, 'DEV-2026-001', 'Devolución por cambio de modelo aprobado por gerencia', 3);

INSERT INTO stock_alerts_config (product_variant_id, min_threshold, is_active, created_by) VALUES
(1, 10, TRUE, 3),
(2, 10, TRUE, 3),
(5, 8, TRUE, 3),  -- Variante 5 tiene stock 4 <= 8 (En alerta crítica)
(8, 25, TRUE, 3),
(12, 5, TRUE, 3), -- Variante 12 tiene stock 3 <= 5 (En alerta crítica)
(15, 12, TRUE, 3),
(16, 10, TRUE, 3);

-- -----------------------------------------------------------------------------
-- 10.6. Poblado del Módulo 6: Ventas, Pagos y Logística Híbrida
-- -----------------------------------------------------------------------------
INSERT INTO order_channels (id, name, description, created_by) VALUES
(1, 'web_b2c', 'Tienda pública de comercio electrónico minorista', 1),
(2, 'web_b2b', 'Portal de pedidos mayoristas con cálculo automático por tramos', 1),
(3, 'pos_presencial', 'Punto de venta físico en tienda comercial', 1);

INSERT INTO order_statuses (id, name, description, created_by) VALUES
(1, 'pendiente', 'Orden creada a la espera de confirmación de pago', 1),
(2, 'procesando', 'Pago confirmado; pedido en preparación de almacén', 1),
(3, 'completado', 'Pedido entregado satisfactoriamente y cerrado', 1),
(4, 'cancelado', 'Pedido anulado antes de su despacho', 1);

INSERT INTO payment_methods (id, name, description, requires_verification, created_by) VALUES
(1, 'tarjeta', 'Pago con tarjeta de crédito o débito vía pasarela', FALSE, 1),
(2, 'transferencia', 'Transferencia bancaria interbancaria (BCP / BBVA / Interbank)', TRUE, 1),
(3, 'efectivo_pos', 'Cobro en efectivo en caja de tienda física', FALSE, 1),
(4, 'yape_plin', 'Pago digital inmediato mediante billetera móvil QR', TRUE, 1);

INSERT INTO payment_statuses (id, name, description, created_by) VALUES
(1, 'pendiente', 'Transacción iniciada pendiente de validación bancaria', 1),
(2, 'confirmado', 'Fondos acreditados y verificados en cuenta', 1),
(3, 'rechazado', 'Operación denegada por la entidad financiera', 1),
(4, 'reembolsado', 'Importe devuelto al cliente por anulación o devolución', 1);

INSERT INTO fulfillment_types (id, name, description, base_cost, created_by) VALUES
(1, 'retiro_tienda', 'Recojo presencial sin costo en tienda principal Miraflores', 0.00, 1),
(2, 'envio_domicilio', 'Entrega motorizada express en Lima Metropolitana', 15.00, 1),
(3, 'agencia_transporte', 'Envío interprovincial asegurado vía Shalom / Olva Courier', 25.00, 1);

INSERT INTO shipping_statuses (id, name, description, created_by) VALUES
(1, 'preparando', 'Picking y embalaje en curso dentro del almacén', 1),
(2, 'listo_para_retiro', 'Paquete preparado en mostrador listo para recojo del cliente', 1),
(3, 'en_camino', 'Pedido en tránsito hacia la dirección de destino', 1),
(4, 'entregado', 'Recepción conformada por el cliente destinatario', 1);

-- Órdenes representativas cubriendo canales B2C, B2B y POS
INSERT INTO orders (id, order_number, user_id, channel_id, status_id, subtotal_amount, shipping_amount, total_amount, notes, created_by) VALUES
-- Orden 1: Venta B2C completada con envío a domicilio en Lima
(1, 'PED-2026-0001', 6, 1, 3, 2449.50, 15.00, 2464.50, 'Entregar en portería del edificio previa llamada.', 6),
-- Orden 2: Venta Mayorista B2B completada (30 camisetas Tramo 4 + 7 balones Tramo 2) con envío agencia a Arequipa
(2, 'PED-2026-0002', 5, 2, 3, 4013.00, 25.00, 4038.00, 'Solicitamos factura electrónica con RUC 20548912341.', 5),
-- Orden 3: Venta presencial POS con retiro inmediato en tienda (costo envío S/ 0.00)
(3, 'PED-2026-0003', 6, 3, 3, 1469.70, 0.00, 1469.70, 'Venta directa en mostrador tienda Miraflores.', 4),
-- Orden 4: Venta web pendiente de validación de transferencia
(4, 'PED-2026-0004', 5, 2, 1, 3294.00, 0.00, 3294.00, 'Cliente recogerá con movilidad propia en almacén central.', 5);

INSERT INTO order_items (order_id, product_variant_id, pricing_tier_id, quantity, unit_price, subtotal, created_by) VALUES
-- Ítems Orden 1 (5 unidades -> Tramo 1 Minorista @ 489.90)
(1, 1, 1, 5, 489.90, 2449.50, 6),
-- Ítems Orden 2 (30 camisetas -> Tramo 4 Mayorista 3 @ 85.00; 7 balones -> Tramo 2 Mayorista 1 @ 209.00)
(2, 8, 4, 30, 85.00, 2550.00, 5),
(2, 16, 2, 7, 209.00, 1463.00, 5),
-- Ítems Orden 3 (3 zapatillas -> Tramo 1 Minorista @ 489.90)
(3, 2, 1, 3, 489.90, 1469.70, 4),
-- Ítems Orden 4 (6 zapatillas -> Tramo 1/2 @ 549.00)
(4, 5, 2, 6, 549.00, 3294.00, 5);

INSERT INTO payments (order_id, payment_method_id, status_id, transaction_reference, amount_paid, paid_at, created_by) VALUES
(1, 1, 2, 'VISANET-98451203', 2464.50, CURRENT_TIMESTAMP - INTERVAL '3 days', 6),
(2, 2, 2, 'BCP-OP-77412589', 4038.00, CURRENT_TIMESTAMP - INTERVAL '2 days', 2),
(3, 3, 2, 'POS-TICKET-00412', 1469.70, CURRENT_TIMESTAMP - INTERVAL '1 day', 4),
(4, 2, 1, 'BBVA-PEND-331098', 3294.00, NULL, 5);

INSERT INTO shipments (order_id, fulfillment_type_id, shipping_status_id, shipping_cost, destination_address, city, tracking_number, dispatched_at, delivered_at, created_by) VALUES
(1, 2, 4, 15.00, 'Av. José Pardo 640, Dpto 802, Miraflores', 'Lima', 'EXP-LIM-2026001', CURRENT_TIMESTAMP - INTERVAL '3 days', CURRENT_TIMESTAMP - INTERVAL '2 days', 3),
(2, 3, 4, 25.00, 'Av. Ejército 710, Yanahuara (Agencia Shalom)', 'Arequipa', 'SHL-AQP-889412', CURRENT_TIMESTAMP - INTERVAL '2 days', CURRENT_TIMESTAMP - INTERVAL '1 day', 3),
(3, 1, 4, 0.00, NULL, 'Lima', 'RETIRO-POS-003', CURRENT_TIMESTAMP - INTERVAL '1 day', CURRENT_TIMESTAMP - INTERVAL '1 day', 4),
(4, 1, 1, 0.00, NULL, 'Lima', 'RETIRO-ALM-004', NULL, NULL, 3);

-- -----------------------------------------------------------------------------
-- 10.7. Poblado del Módulo 7: Branding Corporativo e Identidad Visual Dinámica
-- -----------------------------------------------------------------------------
INSERT INTO company_profiles (id, company_name, tax_id, address, phone_primary, whatsapp_contact, support_email, created_by) VALUES
(1, 'SportCorp Perú S.A.C.', '20608945123', 'Av. Paseo de la República 3450, San Isidro, Lima - Perú', '+51 (01) 442-8900', '+51 999 888 777', 'soporte@sportcorp.pe', 1);

INSERT INTO social_networks (company_profile_id, network_name, profile_url, icon_identifier, is_active, created_by) VALUES
(1, 'Instagram', 'https://instagram.com/sportcorp.peru', 'ri-instagram-line', TRUE, 1),
(1, 'Facebook', 'https://facebook.com/sportcorp.peru', 'ri-facebook-circle-line', TRUE, 1),
(1, 'TikTok', 'https://tiktok.com/@sportcorp.pe', 'ri-tiktok-line', TRUE, 1),
(1, 'LinkedIn', 'https://linkedin.com/company/sportcorp-peru', 'ri-linkedin-box-line', TRUE, 1);

-- Dos paquetes de activos gráficos: 1 activo vigente y 1 histórico inactivo (cumple índice único parcial)
INSERT INTO brand_assets (id, company_profile_id, asset_name, logo_light_url, logo_dark_url, isotype_url, favicon_url, is_active, created_by) VALUES
(1, 1, 'Identidad Institucional Oficial 2026', '/uploads/branding/sportcorp-logo-light.svg', '/uploads/branding/sportcorp-logo-dark.svg', '/uploads/branding/sportcorp-iso.svg', '/uploads/branding/favicon.ico', TRUE, 1),
(2, 1, 'Edición Especial Aniversario 2025 (Histórico)', '/uploads/branding/sportcorp-2025-light.svg', '/uploads/branding/sportcorp-2025-dark.svg', '/uploads/branding/sportcorp-iso-2025.svg', '/uploads/branding/favicon-2025.ico', FALSE, 1);

-- Dos paletas visuales completas: 1 activa y 1 alternativa lista para conmutar con 1 clic
INSERT INTO color_palettes (id, name, description, is_active, created_by) VALUES
(1, 'Ejecutivo Deportivo Minimalista', 'Paleta principal de alto contraste inspirada en tiendas deportivas globales.', TRUE, 1),
(2, 'Campaña Cyber Verano Naranja', 'Paleta de alto impacto comercial para eventos promocionales y descuentos.', FALSE, 1);

INSERT INTO design_tokens (
    color_palette_id, primary_color, secondary_color, accent_color,
    background_primary, background_secondary, surface_card,
    text_primary, text_secondary, font_family_base, border_color,
    button_primary_bg, button_primary_text,
    color_success, color_warning, color_error, color_info, created_by
) VALUES
-- Tokens de la Paleta 1 (Activa)
(
    1, '#0F172A', '#334155', '#2563EB',
    '#F8FAFC', '#F1F5F9', '#FFFFFF',
    '#0F172A', '#64748B', '''Inter'', sans-serif', '#E2E8F0',
    '#0F172A', '#FFFFFF',
    '#16A34A', '#D97706', '#DC2626', '#0284C7', 1
),
-- Tokens de la Paleta 2 (Inactiva - lista para activación dinámica)
(
    2, '#18181B', '#3F3F46', '#EA580C',
    '#FFFFFF', '#FFF7ED', '#FFFFFF',
    '#09090B', '#52525B', '''Inter'', sans-serif', '#FED7AA',
    '#EA580C', '#FFFFFF',
    '#15803D', '#B45309', '#B91C1C', '#0369A1', 1
);

-- -----------------------------------------------------------------------------
-- 10.8. Poblado del Módulo 8: Auditoría Centralizada Inmutable (Audit Logs)
-- -----------------------------------------------------------------------------
INSERT INTO audit_logs (table_name, record_id, action, old_values, new_values, user_id, ip_address) VALUES
('color_palettes', 1, 'INSERT', NULL, '{"name": "Ejecutivo Deportivo Minimalista", "is_active": true}'::jsonb, 1, '190.236.45.12'),
('products', 1, 'INSERT', NULL, '{"name": "Nike Air Zoom Pegasus 41", "is_published": true}'::jsonb, 1, '190.236.45.12'),
('product_volume_prices', 5, 'UPDATE', '{"unit_price": 110.00}'::jsonb, '{"unit_price": 105.00}'::jsonb, 2, '190.236.45.18'),
('orders', 2, 'UPDATE', '{"status_id": 1}'::jsonb, '{"status_id": 3}'::jsonb, 2, '190.236.45.18');

-- =============================================================================
-- SECCIÓN 11: SINCRONIZACIÓN DE SECUENCIAS Y CIERRE DE TRANSACCIÓN
-- =============================================================================

-- Reinicia las secuencias SERIAL al valor máximo actual para evitar colisiones en futuras inserciones
SELECT setval('roles_id_seq', (SELECT MAX(id) FROM roles));
SELECT setval('permissions_id_seq', (SELECT MAX(id) FROM permissions));
SELECT setval('role_permissions_id_seq', (SELECT MAX(id) FROM role_permissions));
SELECT setval('users_id_seq', (SELECT MAX(id) FROM users));
SELECT setval('brands_id_seq', (SELECT MAX(id) FROM brands));
SELECT setval('categories_id_seq', (SELECT MAX(id) FROM categories));
SELECT setval('demographic_segments_id_seq', (SELECT MAX(id) FROM demographic_segments));
SELECT setval('target_genders_id_seq', (SELECT MAX(id) FROM target_genders));
SELECT setval('colors_id_seq', (SELECT MAX(id) FROM colors));
SELECT setval('materials_id_seq', (SELECT MAX(id) FROM materials));
SELECT setval('sizes_id_seq', (SELECT MAX(id) FROM sizes));
SELECT setval('products_id_seq', (SELECT MAX(id) FROM products));
SELECT setval('product_variants_id_seq', (SELECT MAX(id) FROM product_variants));
SELECT setval('product_images_id_seq', (SELECT MAX(id) FROM product_images));
SELECT setval('pricing_tiers_id_seq', (SELECT MAX(id) FROM pricing_tiers));
SELECT setval('product_volume_prices_id_seq', (SELECT MAX(id) FROM product_volume_prices));
SELECT setval('bulk_import_jobs_id_seq', (SELECT MAX(id) FROM bulk_import_jobs));
SELECT setval('bulk_import_errors_id_seq', (SELECT MAX(id) FROM bulk_import_errors));
SELECT setval('inventory_movements_id_seq', (SELECT MAX(id) FROM inventory_movements));
SELECT setval('stock_alerts_config_id_seq', (SELECT MAX(id) FROM stock_alerts_config));
SELECT setval('order_channels_id_seq', (SELECT MAX(id) FROM order_channels));
SELECT setval('order_statuses_id_seq', (SELECT MAX(id) FROM order_statuses));
SELECT setval('payment_methods_id_seq', (SELECT MAX(id) FROM payment_methods));
SELECT setval('payment_statuses_id_seq', (SELECT MAX(id) FROM payment_statuses));
SELECT setval('fulfillment_types_id_seq', (SELECT MAX(id) FROM fulfillment_types));
SELECT setval('shipping_statuses_id_seq', (SELECT MAX(id) FROM shipping_statuses));
SELECT setval('orders_id_seq', (SELECT MAX(id) FROM orders));
SELECT setval('order_items_id_seq', (SELECT MAX(id) FROM order_items));
SELECT setval('payments_id_seq', (SELECT MAX(id) FROM payments));
SELECT setval('shipments_id_seq', (SELECT MAX(id) FROM shipments));
SELECT setval('company_profiles_id_seq', (SELECT MAX(id) FROM company_profiles));
SELECT setval('social_networks_id_seq', (SELECT MAX(id) FROM social_networks));
SELECT setval('brand_assets_id_seq', (SELECT MAX(id) FROM brand_assets));
SELECT setval('color_palettes_id_seq', (SELECT MAX(id) FROM color_palettes));
SELECT setval('design_tokens_id_seq', (SELECT MAX(id) FROM design_tokens));
SELECT setval('audit_logs_id_seq', (SELECT MAX(id) FROM audit_logs));

COMMIT;