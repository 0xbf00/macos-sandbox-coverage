#include "sbpl_helpers.h"

namespace sbpl {
    /**
     * For any given operation, a couple of other operations
     * (mostly more general rules) also apply.
     * This function returns the set of names relevant operations
     * that need to be considered for matching purposes.
     */
    std::set<std::string> relevant_operations(const std::string &op)
    {
        std::set<std::string> result;
        result.insert(op);

        const operation_info_t *op_info = operation_info_for_name(op.c_str());
        if (op_info->node_type == TERMINAL_NODE) {
            // Terminal nodes mean no other operation may interfere.
            return result;
        }

        while (true) {
            op_info = operation_info_for_idx(op_info->fallback_op);


            const size_t idx = operation_idx_for_operation_info(op_info);
            std::string op_name = operation_name_for_idx(idx);

            auto res = result.insert(op_name);

            // Stop if we have already processed this operation name
            if (!std::get<1>(res)) {
                break;
            }
        }

        return result;
    }

    bool operation_default_action(const std::string &op)
    {
        const operation_info_t *op_info = operation_info_for_name(op.c_str());
        return op_info->action;
    }
}