use wasm_bindgen::prelude::*;

use crate::{
    gen_PressureObserverOptions::PressureObserverOptions, gen_PressureSource::PressureSource,
};

#[wasm_bindgen]
extern "C" {
    # [wasm_bindgen (extends = :: web_sys::js_sys :: Object , js_name = PressureObserver , typescript_type = "PressureObserver")]
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[doc = "The `PressureObserver` class."]
    #[doc = ""]
    #[doc = "[MDN Documentation](https://developer.mozilla.org/en-US/docs/Web/API/PressureObserver)"]
    #[doc = ""]
    #[doc = "*This API requires the following crate features to be activated: `PressureObserver`*"]
    #[doc = ""]
    #[doc = "*This API is unstable and requires `--cfg=web_sys_unstable_apis` to be activated, as"]
    #[doc = "[described in the `wasm-bindgen` guide](https://rustwasm.github.io/docs/wasm-bindgen/web-sys/unstable-apis.html)*"]
    pub type PressureObserver;

    # [wasm_bindgen (structural , static_method_of = PressureObserver , getter , js_class = "PressureObserver" , js_name = knownSources)]
    #[doc = "Getter for the `knownSources` field of this object."]
    #[doc = ""]
    #[doc = "[MDN Documentation](https://developer.mozilla.org/en-US/docs/Web/API/PressureObserver/knownSources)"]
    #[doc = ""]
    #[doc = "*This API requires the following crate features to be activated: `PressureObserver`*"]
    #[doc = ""]
    #[doc = "*This API is unstable and requires `--cfg=web_sys_unstable_apis` to be activated, as"]
    #[doc = "[described in the `wasm-bindgen` guide](https://rustwasm.github.io/docs/wasm-bindgen/web-sys/unstable-apis.html)*"]
    pub fn known_sources() -> web_sys::js_sys::Array;

    #[wasm_bindgen(catch, constructor, js_class = "PressureObserver")]
    #[doc = "The `new PressureObserver(..)` constructor, creating a new instance of `PressureObserver`."]
    #[doc = ""]
    #[doc = "[MDN Documentation](https://developer.mozilla.org/en-US/docs/Web/API/PressureObserver/PressureObserver)"]
    #[doc = ""]
    #[doc = "*This API requires the following crate features to be activated: `PressureObserver`*"]
    #[doc = ""]
    #[doc = "*This API is unstable and requires `--cfg=web_sys_unstable_apis` to be activated, as"]
    #[doc = "[described in the `wasm-bindgen` guide](https://rustwasm.github.io/docs/wasm-bindgen/web-sys/unstable-apis.html)*"]
    pub fn new(callback: &web_sys::js_sys::Function) -> Result<PressureObserver, JsValue>;

    # [wasm_bindgen (method , structural , js_class = "PressureObserver" , js_name = disconnect)]
    #[doc = "The `disconnect()` method."]
    #[doc = ""]
    #[doc = "[MDN Documentation](https://developer.mozilla.org/en-US/docs/Web/API/PressureObserver/disconnect)"]
    #[doc = ""]
    #[doc = "*This API requires the following crate features to be activated: `PressureObserver`*"]
    #[doc = ""]
    #[doc = "*This API is unstable and requires `--cfg=web_sys_unstable_apis` to be activated, as"]
    #[doc = "[described in the `wasm-bindgen` guide](https://rustwasm.github.io/docs/wasm-bindgen/web-sys/unstable-apis.html)*"]
    pub fn disconnect(this: &PressureObserver);

    # [wasm_bindgen (method , structural , js_class = "PressureObserver" , js_name = observe)]
    #[doc = "The `observe()` method."]
    #[doc = ""]
    #[doc = "[MDN Documentation](https://developer.mozilla.org/en-US/docs/Web/API/PressureObserver/observe)"]
    #[doc = ""]
    #[doc = "*This API requires the following crate features to be activated: `PressureObserver`, `PressureSource`*"]
    #[doc = ""]
    #[doc = "*This API is unstable and requires `--cfg=web_sys_unstable_apis` to be activated, as"]
    #[doc = "[described in the `wasm-bindgen` guide](https://rustwasm.github.io/docs/wasm-bindgen/web-sys/unstable-apis.html)*"]
    pub fn observe(this: &PressureObserver, source: PressureSource) -> web_sys::js_sys::Promise;

    # [wasm_bindgen (method , structural , js_class = "PressureObserver" , js_name = observe)]
    #[doc = "The `observe()` method."]
    #[doc = ""]
    #[doc = "[MDN Documentation](https://developer.mozilla.org/en-US/docs/Web/API/PressureObserver/observe)"]
    #[doc = ""]
    #[doc = "*This API requires the following crate features to be activated: `PressureObserver`, `PressureObserverOptions`, `PressureSource`*"]
    #[doc = ""]
    #[doc = "*This API is unstable and requires `--cfg=web_sys_unstable_apis` to be activated, as"]
    #[doc = "[described in the `wasm-bindgen` guide](https://rustwasm.github.io/docs/wasm-bindgen/web-sys/unstable-apis.html)*"]
    pub fn observe_with_options(
        this: &PressureObserver,
        source: PressureSource,
        options: &PressureObserverOptions,
    ) -> web_sys::js_sys::Promise;

    # [wasm_bindgen (method , structural , js_class = "PressureObserver" , js_name = takeRecords)]
    #[doc = "The `takeRecords()` method."]
    #[doc = ""]
    #[doc = "[MDN Documentation](https://developer.mozilla.org/en-US/docs/Web/API/PressureObserver/takeRecords)"]
    #[doc = ""]
    #[doc = "*This API requires the following crate features to be activated: `PressureObserver`*"]
    #[doc = ""]
    #[doc = "*This API is unstable and requires `--cfg=web_sys_unstable_apis` to be activated, as"]
    #[doc = "[described in the `wasm-bindgen` guide](https://rustwasm.github.io/docs/wasm-bindgen/web-sys/unstable-apis.html)*"]
    pub fn take_records(this: &PressureObserver) -> web_sys::js_sys::Array;

    # [wasm_bindgen (method , structural , js_class = "PressureObserver" , js_name = unobserve)]
    #[doc = "The `unobserve()` method."]
    #[doc = ""]
    #[doc = "[MDN Documentation](https://developer.mozilla.org/en-US/docs/Web/API/PressureObserver/unobserve)"]
    #[doc = ""]
    #[doc = "*This API requires the following crate features to be activated: `PressureObserver`, `PressureSource`*"]
    #[doc = ""]
    #[doc = "*This API is unstable and requires `--cfg=web_sys_unstable_apis` to be activated, as"]
    #[doc = "[described in the `wasm-bindgen` guide](https://rustwasm.github.io/docs/wasm-bindgen/web-sys/unstable-apis.html)*"]
    pub fn unobserve(this: &PressureObserver, source: PressureSource);
}
