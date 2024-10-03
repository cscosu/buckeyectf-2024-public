#![allow(clippy::all)]

use wasm_bindgen::prelude::*;

use crate::{gen_PressureSource::PressureSource, gen_PressureState::PressureState};

#[wasm_bindgen]
extern "C" {
    # [wasm_bindgen (extends = :: web_sys::js_sys :: Object , js_name = PressureRecord , typescript_type = "PressureRecord")]
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[doc = "The `PressureRecord` class."]
    #[doc = ""]
    #[doc = "[MDN Documentation](https://developer.mozilla.org/en-US/docs/Web/API/PressureRecord)"]
    #[doc = ""]
    #[doc = "*This API requires the following crate features to be activated: `PressureRecord`*"]
    #[doc = ""]
    #[doc = "*This API is unstable and requires `--cfg=web_sys_unstable_apis` to be activated, as"]
    #[doc = "[described in the `wasm-bindgen` guide](https://rustwasm.github.io/docs/wasm-bindgen/web-sys/unstable-apis.html)*"]
    pub type PressureRecord;

    # [wasm_bindgen (structural , method , getter , js_class = "PressureRecord" , js_name = source)]
    #[doc = "Getter for the `source` field of this object."]
    #[doc = ""]
    #[doc = "[MDN Documentation](https://developer.mozilla.org/en-US/docs/Web/API/PressureRecord/source)"]
    #[doc = ""]
    #[doc = "*This API requires the following crate features to be activated: `PressureRecord`, `PressureSource`*"]
    #[doc = ""]
    #[doc = "*This API is unstable and requires `--cfg=web_sys_unstable_apis` to be activated, as"]
    #[doc = "[described in the `wasm-bindgen` guide](https://rustwasm.github.io/docs/wasm-bindgen/web-sys/unstable-apis.html)*"]
    pub fn source(this: &PressureRecord) -> PressureSource;

    # [wasm_bindgen (structural , method , getter , js_class = "PressureRecord" , js_name = state)]
    #[doc = "Getter for the `state` field of this object."]
    #[doc = ""]
    #[doc = "[MDN Documentation](https://developer.mozilla.org/en-US/docs/Web/API/PressureRecord/state)"]
    #[doc = ""]
    #[doc = "*This API requires the following crate features to be activated: `PressureRecord`, `PressureState`*"]
    #[doc = ""]
    #[doc = "*This API is unstable and requires `--cfg=web_sys_unstable_apis` to be activated, as"]
    #[doc = "[described in the `wasm-bindgen` guide](https://rustwasm.github.io/docs/wasm-bindgen/web-sys/unstable-apis.html)*"]
    pub fn state(this: &PressureRecord) -> PressureState;

    # [wasm_bindgen (structural , method , getter , js_class = "PressureRecord" , js_name = time)]
    #[doc = "Getter for the `time` field of this object."]
    #[doc = ""]
    #[doc = "[MDN Documentation](https://developer.mozilla.org/en-US/docs/Web/API/PressureRecord/time)"]
    #[doc = ""]
    #[doc = "*This API requires the following crate features to be activated: `PressureRecord`*"]
    #[doc = ""]
    #[doc = "*This API is unstable and requires `--cfg=web_sys_unstable_apis` to be activated, as"]
    #[doc = "[described in the `wasm-bindgen` guide](https://rustwasm.github.io/docs/wasm-bindgen/web-sys/unstable-apis.html)*"]
    pub fn time(this: &PressureRecord) -> f64;

    # [wasm_bindgen (method , structural , js_class = "PressureRecord" , js_name = toJSON)]
    #[doc = "The `toJSON()` method."]
    #[doc = ""]
    #[doc = "[MDN Documentation](https://developer.mozilla.org/en-US/docs/Web/API/PressureRecord/toJSON)"]
    #[doc = ""]
    #[doc = "*This API requires the following crate features to be activated: `PressureRecord`*"]
    #[doc = ""]
    #[doc = "*This API is unstable and requires `--cfg=web_sys_unstable_apis` to be activated, as"]
    #[doc = "[described in the `wasm-bindgen` guide](https://rustwasm.github.io/docs/wasm-bindgen/web-sys/unstable-apis.html)*"]
    pub fn to_json(this: &PressureRecord) -> web_sys::js_sys::Object;
}
